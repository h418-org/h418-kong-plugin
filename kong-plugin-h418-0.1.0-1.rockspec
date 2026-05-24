package = "kong-plugin-h418"
version = "0.1.0-1"
source = {
  url = "git+https://github.com/h418/h418-org.git",
  tag = "v0.1.0"
}
description = {
  summary = "H418 stateless anti-automation plugin for Kong",
  detailed = "Kong plugin that enforces H418 challenges, proof verification, scoring, and credential issuance inside Kong.",
  homepage = "https://h418.org",
  license = "MIT"
}
dependencies = {
  "lua >= 5.1",
  "lua-resty-http",
  "lua-resty-openssl"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.h418.handler"] = "kong/plugins/h418/handler.lua",
    ["kong.plugins.h418.schema"] = "kong/plugins/h418/schema.lua",
    ["kong.plugins.h418.core"] = "kong/plugins/h418/core.lua"
  }
}
