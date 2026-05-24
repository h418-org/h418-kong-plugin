local h418 = require "kong.plugins.h418.core"

local function debug_payload(decision)
  local budget = decision.budget or decision.anonymous_budget
  return {
    allowed = decision.allowed,
    mode = decision.mode,
    reason = decision.reason,
    score = decision.score,
    budget = budget and {
      count = budget.count,
      remaining = budget.remaining,
      over_soft = budget.over_soft,
      over_hard = budget.over_hard,
      refresh_eligible = budget.refresh_eligible
    } or nil
  }
end

local function debug(conf, decision)
  if not conf.debug then
    return nil
  end
  local cjson = require "cjson.safe"
  local payload = cjson.encode(debug_payload(decision))
  kong.log.info("h418 decision: ", payload)
  return payload
end

local H418Handler = {
  VERSION = "0.1.0",
  PRIORITY = 1000
}

local function policy(conf)
  return h418.policy({
    origin = conf.origin,
    key_id = conf.key_id,
    public_key = conf.public_key,
    credential_ttl_seconds = conf.credential_ttl_seconds
  })
end

function H418Handler:access(conf)
  if kong.request.get_method() == "GET" and kong.request.get_path() == "/.well-known/h418-policy" then
    return kong.response.exit(200, policy(conf), {
      ["content-type"] = "application/json; charset=utf-8"
    })
  end

  local ok, decision = pcall(h418.decide, {
    origin = conf.origin,
    key_id = conf.key_id,
    private_key = conf.private_key,
    public_key = conf.public_key,
    status_code = conf.status_code,
    challenge_ttl_seconds = conf.challenge_ttl_seconds,
    credential_ttl_seconds = conf.credential_ttl_seconds,
    external_enabled = conf.external_enabled,
    external_top_n = conf.external_top_n,
    external_max_total_score = conf.external_max_total_score,
    external_max_per_issuer_score = conf.external_max_per_issuer_score,
    external_max_pow_reduction = conf.external_max_pow_reduction,
    skip_pow_own_score = conf.skip_pow_own_score,
    own_score_reduction_step = conf.own_score_reduction_step,
    budget_enabled = conf.budget_enabled,
    budget_window_seconds = conf.budget_window_seconds,
    budget_soft_limit = conf.budget_soft_limit,
    budget_hard_limit = conf.budget_hard_limit,
	    budget_penalty_per_request_over_soft = conf.budget_penalty_per_request_over_soft,
	    budget_bonus_inside_budget = conf.budget_bonus_inside_budget,
	    anonymous_grace = conf.anonymous_grace,
	    anonymous_budget_enabled = conf.anonymous_budget_enabled,
	    anonymous_budget_window_seconds = conf.anonymous_budget_window_seconds,
	    anonymous_budget_soft_limit = conf.anonymous_budget_soft_limit,
	    anonymous_budget_hard_limit = conf.anonymous_budget_hard_limit,
	    budget_dict = ngx.shared.h418_budget
	  }, {
    method = kong.request.get_method(),
    path = conf.route_path or kong.request.get_path(),
    scope = conf.scope,
	    min_score = conf.min_score,
	    fallback_pow_difficulty = conf.pow_difficulty,
	    high_risk = conf.high_risk,
	    anonymous_key = (kong.client.get_forwarded_ip() or "unknown") .. ":" .. (kong.request.get_header("User-Agent") or "unknown"),
	    challenge = kong.request.get_header("H418-Challenge"),
	    presentation = kong.request.get_header("H418-Presentation")
	  })

  if not ok then
    kong.log.err("h418 decision failed: ", decision)
    return kong.response.exit(500, {
      error = "h418_plugin_error"
    })
  end

	  local debug_header = debug(conf, decision)

	  if decision.allowed then
	    if decision.credential then
	      kong.response.set_header("H418-Credential", decision.credential)
	    end
	    if decision.score then
	      kong.response.set_header("H418-Score", tostring(decision.score))
	    end
	    if decision.challenge then
	      kong.response.set_header("H418-Challenge", decision.challenge)
	    end
	    if decision.mode then
	      kong.response.set_header("H418-Mode", decision.mode)
	    end
	    if decision.budget and decision.budget.remaining ~= nil then
	      kong.response.set_header("H418-Budget-Remaining", tostring(decision.budget.remaining))
	    elseif decision.anonymous_budget and decision.anonymous_budget.remaining ~= nil then
	      kong.response.set_header("H418-Budget-Remaining", tostring(decision.anonymous_budget.remaining))
	    end
	    if debug_header then
	      kong.response.set_header("H418-Debug", debug_header)
	    end
	    return
	  end

	  local headers = {
	    ["H418-Challenge"] = decision.challenge,
	    ["H418-Reason"] = decision.reason,
	    ["content-type"] = "application/json; charset=utf-8"
	  }
	  if decision.mode then
	    headers["H418-Mode"] = decision.mode
	  end
	  if debug_header then
	    headers["H418-Debug"] = debug_header
	  end

	  return kong.response.exit(decision.status or 403, {
	    error = "h418_required",
	    reason = decision.reason,
	    challenge = decision.challenge
	  }, headers)
end

return H418Handler
