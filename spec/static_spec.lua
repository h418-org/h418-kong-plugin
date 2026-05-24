local files = {
  "kong-plugin/kong/plugins/h418/handler.lua",
  "kong-plugin/kong/plugins/h418/schema.lua",
  "kong-plugin/kong-plugin-h418-0.1.0-1.rockspec"
}

for _, file in ipairs(files) do
  local handle = assert(io.open(file, "r"))
  local content = handle:read("*a")
  handle:close()
  assert(content:match("h418") or content:match("H418"), file .. " should contain H418 logic")
end

print("kong-plugin static tests passed")
