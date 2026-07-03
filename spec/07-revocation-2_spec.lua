local session = require "resty.session"
local redis_storage = require "resty.session.redis"
local encode_base64url = require("resty.session.utils").encode_base64url


local before_each = before_each
local describe = describe
local assert = assert
local pcall = pcall
local ipairs = ipairs
local it = it


local redis_config = {
  host = "127.0.0.1",
  password = "password",
}


local bad_redis_config = {
  host = "127.0.0.1",
  port = 1,
  password = "password",
  connect_timeout = 100,
  send_timeout = 100,
  read_timeout = 100,
}


local function revocation_redis(config)
  local cfg = {}
  for k, v in pairs(config) do
    cfg[k] = v
  end
  cfg.mode = "revocation"
  return cfg
end


local function extract_cookie(cookie_name, cookies)
  local session_cookie
  if type(cookies) == "table" then
    for _, v in ipairs(cookies) do
      session_cookie = ngx.re.match(v, cookie_name .. "=([\\w-]+);")
      if session_cookie then
        return session_cookie[1]
      end
    end
    return ""
  end
  session_cookie = ngx.re.match(cookies, cookie_name .. "=([\\w-]+);")
  return session_cookie and session_cookie[1] or ""
end


describe("Revocation tests 2", function()
  local long_ttl = 60
  local id       = "test_id_1iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
  local id1      = "test_id_2iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
  local cookie   = "session_cookie"

  describe("[#redis] revocation: failures", function()
    it("SET: connection failure returns error", function()
      local bad_store = redis_storage.new(bad_redis_config)

      local ok, err = bad_store:set(cookie, encode_base64url(id), "1", long_ttl, ngx.time())
      assert.is_nil(ok)
      assert.is_not_nil(err)
    end)

    it("GET: connection failure returns error", function()
      local bad_store = redis_storage.new(bad_redis_config)

      local data, err = bad_store:get(cookie, encode_base64url(id1), ngx.time())
      assert.is_nil(data)
      assert.is_not_nil(err)
    end)
  end)

  describe("session: Fields validation", function()
    local configuration = {}
    local cookie_name   = "session_cookie"

    before_each(function()
      configuration = {
        cookie_name = cookie_name,
        redis = redis_config,
      }
      session.init(configuration)
    end)

    it("new loads redis revocation when redis mode is revocation", function()
      local s = session.new({
        storage = "cookie",
        redis = {
          host = redis_config.host,
          password = redis_config.password,
          mode = "revocation",
        },
      })
      assert.is_not_nil(s.revocation)
      assert.is_function(s.revocation.set)
      assert.is_function(s.revocation.get)
    end)

    it("new validates revocation configuration", function()
      local ok, err = pcall(session.new, {
        revocation = 123,
      })
      assert.is_false(ok)
      assert.matches("invalid session revocation", err)
    end)
  end)

  describe("session: open", function()
    local configuration = {}
    local cookie_name   = "session_cookie"
    local test_key      = "test_key"
    local value         = "test_data"

    local function save_session(s, cookies)
      session.__set_ngx_header(cookies)
      s:set(test_key, value)
      local ok, err = s:save()
      assert.is_true(ok)
      assert.is_nil(err)
      return extract_cookie(cookie_name, cookies["Set-Cookie"])
    end

    local function open_session(session_cookie)
      local s = session.new()
      session.__set_ngx_var({
        ["cookie_" .. cookie_name] = session_cookie,
      })

      local ok, err = s:open()
      if not ok then
        return nil, err
      end

      return s
    end

    before_each(function()
      configuration = {
        cookie_name = cookie_name,
        redis = redis_config,
      }
      session.init(configuration)
    end)

    it("open: closed fail mode rejects when redis is unreachable", function()
      local cookies = {}
      local s = session.new()
      local session_cookie = save_session(s, cookies)
      s:close()

      session.init({
        cookie_name = cookie_name,
        redis = revocation_redis(bad_redis_config),
        revocation_fail_mode = "closed",
      })

      local opened, err = open_session(session_cookie)
      assert.is_nil(opened)
      assert.matches("unable to check session revocation", err)
    end)
  end)

  describe("session: revocation_fail_mode", function()
    local configuration = {}
    local cookie_name   = "session_cookie"
    local test_key      = "test_key"
    local value         = "test_data"
    local session_cookie
    local cookies

    local function save_session(s, cookies)
      session.__set_ngx_header(cookies)
      s:set(test_key, value)
      local ok, err = s:save()
      assert.is_true(ok)
      assert.is_nil(err)
      return extract_cookie(cookie_name, cookies["Set-Cookie"])
    end

    local function open_session(session_cookie)
      local s = session.new()
      session.__set_ngx_var({
        ["cookie_" .. cookie_name] = session_cookie,
      })

      local ok, err = s:open()
      if not ok then
        return nil, err
      end

      return s
    end

    before_each(function()
      configuration = {
        cookie_name = cookie_name,
        redis = redis_config,
      }
      session.init(configuration)

      cookies = {}
      local s = session.new()
      session_cookie = save_session(s, cookies)
      s:close()
    end)

    it("destroy: closed fail mode fails when marking revoked fails", function()
      local s = session.new({
        revocation = {
          set = function()
            return nil, "connection refused"
          end,
          get = function()
            return nil
          end,
        },
        revocation_fail_mode = "closed",
      })
      session.__set_ngx_var({
        ["cookie_" .. cookie_name] = session_cookie,
      })

      local ok, err = s:open()
      assert.is_true(ok)
      assert.is_nil(err)

      session.__set_ngx_header(cookies)
      ok, err = s:destroy()
      assert.is_nil(ok)
      assert.matches("unable to mark session revoked", err)
      assert.equals("open", s.state)
    end)

    it("destroy: open fail mode succeeds when marking revoked fails", function()
      session.init({
        cookie_name = cookie_name,
        redis = revocation_redis(bad_redis_config),
        revocation_fail_mode = "open",
      })

      local s = session.new()
      session.__set_ngx_var({
        ["cookie_" .. cookie_name] = session_cookie,
      })

      local ok, err = s:open()
      assert.is_true(ok)
      assert.is_nil(err)

      session.__set_ngx_header(cookies)
      ok, err = s:destroy()
      assert.is_true(ok)
      assert.is_nil(err)
      assert.equals("closed", s.state)
    end)

    it("open: open fail mode succeeds when redis is unreachable", function()
      session.init({
        cookie_name = cookie_name,
        redis = revocation_redis(bad_redis_config),
        revocation_fail_mode = "open",
      })

      local opened, err = open_session(session_cookie)
      assert.is_true(opened)
      assert.is_nil(err)
      assert.equals(value, opened:get(test_key))
    end)
  end)
end)
