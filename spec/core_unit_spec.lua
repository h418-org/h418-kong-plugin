package.preload["cjson.safe"] = function()
  local json = {}
  json.null = {}
  function json.encode(value)
    local kind = type(value)
    if kind == "string" then
      return '"' .. value:gsub("\\", "\\\\"):gsub('"', '\\"') .. '"'
    end
    if kind == "number" or kind == "boolean" then
      return tostring(value)
    end
    if value == json.null then
      return "null"
    end
    error("test json encoder only supports scalar values")
  end
  return json
end

package.preload["resty.http"] = function()
  return {}
end

package.preload["resty.openssl.pkey"] = function()
  return {}
end

package.preload["resty.random"] = function()
  return {}
end

package.preload["resty.sha256"] = function()
  return {}
end

package.preload["resty.string"] = function()
  return {}
end

package.path = "kong-plugin/?.lua;kong-plugin/?/?.lua;" .. package.path

local h418 = require "kong.plugins.h418.core"

assert(h418.canonical_json({ b = 2, a = 1 }) == '{"a":1,"b":2}')
assert(h418.canonical_json({ z = { 2, 1 }, a = true }) == '{"a":true,"z":[2,1]}')

local policy = h418.policy({
  origin = "https://example.test",
  key_id = "h418-test",
  public_key = "pub",
  credential_ttl_seconds = 60
})

assert(policy.h418 == "0.1")
assert(policy.origin == "https://example.test")
assert(policy.issuer_keys[1].public_key == "pub")

print("kong-plugin core unit tests passed")
