local session = require "resty.session"
local redis_storage = require "resty.session.redis"
local encode_base64url = require("resty.session.utils").encode_base64url


local before_each = before_each
local lazy_setup = lazy_setup
local describe = describe
local assert = assert
local ipairs = ipairs
local sleep = ngx.sleep
local it = it


local redis_config = {
  host = "127.0.0.1",
  password = "password",
}


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


describe("Revocation tests 1", function()
  local store
  local long_ttl  = 60
  local short_ttl = 2
  local id        = "test_id_1iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
  local id1       = "test_id_2iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
  local id2       = "test_id_3iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii"
  local cookie    = "session_cookie"

  lazy_setup(function()
    store = redis_storage.new(redis_config)
    assert.is_not_nil(store)
  end)

  describe("session: normal use", function()
    local cookie_name = "session_cookie"
    local test_key    = "test_key"
    local value       = "test_data"

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
      session.init({
        cookie_name = cookie_name,
        storage = "cookie",
        redis = {
          host = redis_config.host,
          password = redis_config.password,
          mode = "revocation",
        },
      })
    end)

    it("open succeeds for a valid session with revocation enabled", function()
      local cookies = {}
      local s = session.new()
      local session_cookie = save_session(s, cookies)
      s:close()

      local s2, err = open_session(session_cookie)
      assert.is_not_nil(s2)
      assert.is_nil(err)
      assert.equals(value, s2:get(test_key))
      s2:close()
    end)

    it("destroy: rejected cookie cannot be reopened", function()
      local cookies = {}
      local s = session.new()
      local session_cookie = save_session(s, cookies)
      assert.is_not_equal("", session_cookie)

      s:close()

      local s2, err = open_session(session_cookie)
      assert.is_not_nil(s2)
      assert.is_nil(err)
      assert.equals(value, s2:get(test_key))

      session.__set_ngx_header(cookies)
      local ok
      ok, err = s2:destroy()
      assert.is_true(ok)
      assert.is_nil(err)

      local s3
      s3, err = open_session(session_cookie)
      assert.is_nil(s3)
      assert.equals("session revoked", err)
    end)

    it("save rotation does not revoke the previous cookie", function()
      local cookies = {}
      local s = session.new()
      local session_cookie = save_session(s, cookies)
      s:close()

      local s2, err = open_session(session_cookie)
      assert.is_not_nil(s2)
      assert.is_nil(err)

      s2:set(test_key, "rotated")
      session.__set_ngx_header(cookies)
      local ok
      ok, err = s2:save()
      assert.is_true(ok)
      assert.is_nil(err)
      s2:close()

      local s3
      s3, err = open_session(session_cookie)
      assert.is_not_nil(s3)
      assert.is_nil(err)
      assert.equals(value, s3:get(test_key))
      s3:close()
    end)

    it("cookie session without revocation clears cookie on destroy", function()
      session.init({
        cookie_name = cookie_name,
        storage = "cookie",
      })

      local cookies = {}
      local s = session.new()
      local session_cookie = save_session(s, cookies)
      s:close()

      local s2, err = open_session(session_cookie)
      assert.is_not_nil(s2)
      assert.is_nil(err)

      session.__set_ngx_header(cookies)
      local ok
      ok, err = s2:destroy()
      assert.is_true(ok)
      assert.is_nil(err)

      local s3
      s3, err = open_session(session_cookie)
      assert.is_nil(s3)
      assert.is_not_equal("session revoked", err)
    end)
  end)

  describe("[#redis] revocation: SET + GET", function()
    it("SET: stores revocation mark and GET observes it", function()
      local ok, err = store:set(cookie, encode_base64url(id1), "1", long_ttl, ngx.time())
      assert.is_not_nil(ok)
      assert.is_nil(err)

      local data
      data, err = store:get(cookie, encode_base64url(id1), ngx.time())
      assert.is_nil(err)
      assert.equals("1", data)
    end)

    it("GET: missing revocation key returns not revoked marker", function()
      local data, err = store:get(cookie, encode_base64url(id), ngx.time())
      assert.is_nil(err)
      assert.is_not_equal("1", data)
    end)

    it("SET: ttl expires revocation entry", function()
      local ok, err = store:set(cookie, encode_base64url(id2), "1", short_ttl, ngx.time())
      assert.is_not_nil(ok)
      assert.is_nil(err)

      local data
      data, err = store:get(cookie, encode_base64url(id2), ngx.time())
      assert.is_nil(err)
      assert.equals("1", data)

      sleep(short_ttl + 1)

      data, err = store:get(cookie, encode_base64url(id2), ngx.time())
      assert.is_nil(err)
      assert.is_not_equal("1", data)
    end)
  end)

  describe("session: configuration", function()
    local configuration = {}
    local cookie_name   = "session_cookie"

    before_each(function()
      configuration = {
        cookie_name = cookie_name,
        redis = redis_config,
      }
      session.init(configuration)
    end)

    it("loads revocation when storage is cookie and redis mode is revocation", function()
      session.init({
        cookie_name = cookie_name,
        storage = "cookie",
        redis = {
          host = redis_config.host,
          password = redis_config.password,
          mode = "revocation",
        },
      })

      local s = session.new()
      assert.is_not_nil(s.revocation)
      assert.is_function(s.revocation.set)
      assert.is_function(s.revocation.get)
    end)

    it("loads revocation when cookie storage has redis without storage mode", function()
      local s = session.new()
      assert.is_not_nil(s.revocation)
      assert.is_function(s.revocation.set)
      assert.is_function(s.revocation.get)
    end)

    it("skips revocation when storage backend is configured", function()
      session.init({
        cookie_name = cookie_name,
        storage = "redis",
        redis = {
          prefix = "sessions",
          password = "password",
        },
      })

      local s = session.new()
      assert.is_nil(s.revocation)
    end)

    it("skips revocation when storage is cookie and redis mode is storage", function()
      session.init({
        cookie_name = cookie_name,
        storage = "cookie",
        redis = {
          host = redis_config.host,
          password = redis_config.password,
          mode = "storage",
        },
      })

      local s = session.new()
      assert.is_nil(s.revocation)
    end)

    it("does not load revocation without a redis host", function()
      session.init({
        cookie_name = cookie_name,
        redis = { password = "password" },
      })

      local s = session.new()
      assert.is_nil(s.revocation)
    end)

    it("skips revocation when revocation is explicitly false", function()
      session.init({
        cookie_name = cookie_name,
        redis = redis_config,
        revocation = false,
      })

      local s = session.new()
      assert.is_nil(s.revocation)
    end)
  end)
end)
