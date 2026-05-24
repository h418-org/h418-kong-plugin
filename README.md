# kong-plugin-h418

Kong OSS plugin for H418.

The plugin is packaged for LuaRocks as `kong-plugin-h418`. Configure Kong with:

```sh
KONG_PLUGINS=bundled,h418
```

The plugin performs Ed25519 protocol validation, PoW verification, scoring, and credential issuance inside Kong. It remains stateless and does not require a separate verifier service.
