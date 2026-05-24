return {
  name = "h418",
  fields = {
    {
      config = {
        type = "record",
        fields = {
          { origin = { type = "string", required = true } },
          { key_id = { type = "string", required = true, default = "h418-dev" } },
          { private_key = { type = "string", required = true } },
          { public_key = { type = "string", required = true } },
          { status_code = { type = "integer", required = true, default = 418, one_of = { 418, 403, 429 } } },
          { challenge_ttl_seconds = { type = "integer", required = true, default = 60 } },
          { scope = { type = "string", required = true, default = "read" } },
          { route_path = { type = "string", required = false } },
          { min_score = { type = "integer", required = true, default = 20 } },
          { pow_difficulty = { type = "integer", required = true, default = 3 } },
          { skip_pow_own_score = { type = "integer", required = true, default = 25 } },
          { own_score_reduction_step = { type = "integer", required = true, default = 10 } },
          { high_risk = { type = "boolean", required = true, default = false } },
          { credential_ttl_seconds = { type = "integer", required = true, default = 3600 } },
          { external_enabled = { type = "boolean", required = true, default = true } },
          { external_top_n = { type = "integer", required = true, default = 3 } },
          { external_max_total_score = { type = "integer", required = true, default = 15 } },
          { external_max_per_issuer_score = { type = "integer", required = true, default = 8 } },
          { external_max_pow_reduction = { type = "integer", required = true, default = 2 } },
          { budget_enabled = { type = "boolean", required = true, default = true } },
          { budget_window_seconds = { type = "integer", required = true, default = 60 } },
	          { budget_soft_limit = { type = "integer", required = true, default = 30 } },
	          { budget_hard_limit = { type = "integer", required = true, default = 60 } },
	          { budget_penalty_per_request_over_soft = { type = "integer", required = true, default = 3 } },
	          { budget_bonus_inside_budget = { type = "integer", required = true, default = 5 } },
	          { anonymous_grace = { type = "boolean", required = true, default = true } },
	          { anonymous_budget_enabled = { type = "boolean", required = true, default = true } },
	          { anonymous_budget_window_seconds = { type = "integer", required = true, default = 60 } },
	          { anonymous_budget_soft_limit = { type = "integer", required = true, default = 5 } },
	          { anonymous_budget_hard_limit = { type = "integer", required = true, default = 15 } },
	          { debug = { type = "boolean", required = true, default = false } }
	        }
      }
    }
  }
}
