local cjson = require "cjson.safe"
local http = require "resty.http"
local pkey = require "resty.openssl.pkey"
local random = require "resty.random"
local sha256 = require "resty.sha256"
local resty_string = require "resty.string"

local _M = {}

_M.VERSION = "0.1"

local local_budget_counters = {}

local function json_quote(value)
  local replacements = {
    ['"'] = '\\"',
    ["\\"] = "\\\\",
    ["\b"] = "\\b",
    ["\f"] = "\\f",
    ["\n"] = "\\n",
    ["\r"] = "\\r",
    ["\t"] = "\\t"
  }
  return '"' .. value:gsub('[%z\1-\31\\"]', function(char)
    return replacements[char] or string.format("\\u%04x", char:byte())
  end) .. '"'
end

local function clone_without_signature(value)
  local out = {}
  for k, v in pairs(value or {}) do
    if k ~= "signature" then
      out[k] = v
    end
  end
  return out
end

local function is_array(value)
  if type(value) ~= "table" then
    return false
  end
  local max = 0
  local count = 0
  for k, _ in pairs(value) do
    if type(k) ~= "number" then
      return false
    end
    if k > max then
      max = k
    end
    count = count + 1
  end
  return max == count
end

function _M.canonical_json(value)
  local kind = type(value)
  if kind ~= "table" then
    if kind == "string" then
      return json_quote(value)
    end
    return cjson.encode(value)
  end
  if is_array(value) then
    local parts = {}
    for i = 1, #value do
      parts[#parts + 1] = _M.canonical_json(value[i])
    end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  local keys = {}
  for k, v in pairs(value) do
    if v ~= nil then
      keys[#keys + 1] = k
    end
  end
  table.sort(keys)
  local parts = {}
  for _, key in ipairs(keys) do
    parts[#parts + 1] = json_quote(key) .. ":" .. _M.canonical_json(value[key])
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

function _M.base64url_encode(value)
  return ngx.encode_base64(value):gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
end

function _M.base64url_decode(value)
  local input = value:gsub("-", "+"):gsub("_", "/")
  local pad = #input % 4
  if pad == 2 then
    input = input .. "=="
  elseif pad == 3 then
    input = input .. "="
  elseif pad ~= 0 then
    return nil
  end
  return ngx.decode_base64(input)
end

function _M.encode_token(value)
  return _M.base64url_encode(_M.canonical_json(value))
end

function _M.decode_token(token)
  local decoded = _M.base64url_decode(token)
  if not decoded then
    return nil
  end
  return cjson.decode(decoded)
end

local function key_from_config(encoded_key)
  if not encoded_key then
    return nil, "missing_key"
  end
  if encoded_key:find("-----BEGIN", 1, true) then
    return pkey.new(encoded_key)
  end
  local der = _M.base64url_decode(encoded_key)
  if not der then
    return nil, "bad_base64url_key"
  end
  return pkey.new(der, { format = "DER" })
end

function _M.sign_object(object, private_key)
  local key, err = key_from_config(private_key)
  if not key then
    return nil, err
  end
  local signature
  signature, err = key:sign(_M.canonical_json(clone_without_signature(object)))
  if not signature then
    return nil, err
  end
  return _M.base64url_encode(signature)
end

function _M.verify_object(object, public_key)
  if not object or not object.signature then
    return false
  end
  local key = key_from_config(public_key)
  if not key then
    return false
  end
  local signature = _M.base64url_decode(object.signature)
  if not signature then
    return false
  end
  return key:verify(signature, _M.canonical_json(clone_without_signature(object))) == true
end

local function now()
  return ngx.time()
end

local function iso_time(epoch)
  return os.date("!%Y-%m-%dT%H:%M:%SZ", epoch)
end

local function timezone_offset()
  local current = os.time()
  return os.difftime(os.time(os.date("*t", current)), os.time(os.date("!*t", current)))
end

local function parse_iso(value)
  if type(value) ~= "string" then
    return nil
  end
  local y, m, d, h, mi, s = value:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)Z$")
  if not y then
    return nil
  end
  return os.time({
    year = tonumber(y),
    month = tonumber(m),
    day = tonumber(d),
    hour = tonumber(h),
    min = tonumber(mi),
    sec = tonumber(s)
  }) + timezone_offset()
end

local function fresh(object)
  local expires_at = object and (object.expires_at or (object.lifecycle and object.lifecycle.expires_at))
  local expiry = parse_iso(expires_at)
  return expiry ~= nil and expiry > now()
end

local function random_id(prefix)
  return prefix .. _M.base64url_encode(random.bytes(16, true))
end

function _M.policy(conf)
  return {
    h418 = _M.VERSION,
    origin = conf.origin,
    issuer_keys = {
      {
        key_id = conf.key_id,
        algorithm = "Ed25519",
        public_key = conf.public_key
      }
    },
    proofs = {
      pow = true,
      client_signature = true,
      signed_credentials = true,
      agent_intent = true
    },
    credentials = {
      issues = true,
      types = { "recent_good_behavior", "human_attention_light", "agent_compliance" },
      default_ttl_seconds = conf.credential_ttl_seconds or 3600
    }
  }
end

function _M.create_challenge(conf, request)
  local issued_at = now()
  local challenge = {
    h418_challenge = _M.VERSION,
    issuer = {
      origin = conf.origin,
      key_id = conf.key_id
    },
    challenge_id = random_id("ch_"),
    nonce = _M.base64url_encode(random.bytes(16, true)),
    scope = request.scope,
    method = request.method,
    path = request.path,
    issued_at = iso_time(issued_at),
    expires_at = iso_time(issued_at + (conf.challenge_ttl_seconds or 60)),
    required = {
      client_signature = true,
      pow = {
        difficulty = request.fallback_pow_difficulty or 4,
        min_difficulty = 0,
        skip_with_own_score = conf.skip_pow_own_score or 25,
        own_score_reduction_step = conf.own_score_reduction_step or 10,
        external_score_reduction_step = 8
      },
      budget = {
        window_seconds = conf.budget_window_seconds or 60,
        soft_limit = conf.budget_soft_limit or 30,
        hard_limit = conf.budget_hard_limit or 60
      },
      accepted_credentials = { "recent_good_behavior", "human_attention_light", "agent_compliance" },
      top_n_credentials = conf.external_top_n or 3
    }
  }
  challenge.signature = assert(_M.sign_object(challenge, conf.private_key))
  return challenge
end

function _M.pow_digest(challenge, subject_public_key, pow_nonce)
  local digest = sha256:new()
  digest:update(table.concat({
    challenge.challenge_id,
    challenge.nonce,
    subject_public_key,
    pow_nonce
  }, "."))
  return resty_string.to_hex(digest:final())
end

function _M.verify_pow(challenge, subject_public_key, pow_nonce, difficulty)
  if not pow_nonce then
    return false
  end
  return _M.pow_digest(challenge, subject_public_key, pow_nonce):sub(1, difficulty) == string.rep("0", difficulty)
end

local function presentation_binding(presentation)
  local credential_ids = {}
  for _, credential in ipairs(presentation.credentials or {}) do
    credential_ids[#credential_ids + 1] = credential.credential_id
  end
  return {
    h418_presentation = _M.VERSION,
    audience = presentation.audience,
    challenge_id = presentation.challenge_id,
    subject_public_key = presentation.subject_public_key,
    pow_nonce = presentation.pow_nonce,
    credential_ids = credential_ids,
    agent_intent = presentation.agent_intent or cjson.null
  }
end

local function verify_presentation_signature(presentation)
  local binding = presentation_binding(presentation)
  binding.signature = presentation.client_signature
  return _M.verify_object(binding, presentation.subject_public_key)
end

local function discover_public_key(credential)
  local httpc = http.new()
  local response = httpc:request_uri(credential.issuer.origin .. "/.well-known/h418-policy", {
    method = "GET"
  })
  if not response or response.status >= 400 then
    return nil
  end
  local policy = cjson.decode(response.body)
  for _, key in ipairs(policy.issuer_keys or {}) do
    if key.key_id == credential.issuer.key_id then
      return key.public_key
    end
  end
  return nil
end

local function verify_credential(conf, credential, subject_public_key, scope)
  if not credential or not credential.subject or credential.subject.public_key ~= subject_public_key then
    return { valid = false, own = false, score = 0, reason = "subject_mismatch" }
  end
  if not fresh(credential) then
    return { valid = false, own = false, score = 0, reason = "expired" }
  end
  if not credential.claims or credential.claims.scope ~= scope then
    return { valid = false, own = false, score = 0, reason = "scope_mismatch" }
  end

  local own = credential.issuer.origin == conf.origin and credential.issuer.key_id == conf.key_id
  local public_key = own and conf.public_key or discover_public_key(credential)
  if not public_key or not _M.verify_object(credential, public_key) then
    return { valid = false, own = own, score = 0, reason = "bad_signature" }
  end

  return {
    valid = true,
    own = own,
    score = _M.effective_credential_score(credential),
    raw_score = tonumber(credential.claims.score) or 0,
    sequence = tonumber(credential.lifecycle and credential.lifecycle.sequence) or 0,
    issuer_origin = credential.issuer.origin
  }
end

function _M.effective_credential_score(credential)
  local raw_score = tonumber(credential and credential.claims and credential.claims.score) or 0
  local issued_at = parse_iso(credential and credential.lifecycle and credential.lifecycle.issued_at)
  local expires_at = parse_iso(credential and credential.lifecycle and credential.lifecycle.expires_at)
  if raw_score <= 0 or not issued_at or not expires_at or expires_at <= issued_at then
    return 0
  end
  local freshness = math.max(0, math.min(1, (expires_at - now()) / (expires_at - issued_at)))
  return math.ceil(raw_score * freshness)
end

local function score_external(results, conf)
  if conf.external_enabled == false then
    return 0
  end
  local seen = {}
  local total = 0
  for _, result in ipairs(results) do
    if result.valid and not result.own and not seen[result.issuer_origin] then
      seen[result.issuer_origin] = true
      total = total + math.min(result.score, conf.external_max_per_issuer_score or 8)
    end
  end
  return math.min(total, conf.external_max_total_score or 15)
end

local function effective_pow_difficulty(fallback_difficulty, own_score, external_score, conf)
  if own_score >= (conf.skip_pow_own_score or 25) then
    return 0
  end
  local own_reduction = math.floor(own_score / (conf.own_score_reduction_step or 10))
  local external_reduction = 0
  if external_score > 0 then
    external_reduction = math.min(conf.external_max_pow_reduction or 2, math.ceil(external_score / 8))
  end
  return math.max(1, fallback_difficulty - own_reduction - external_reduction)
end

local function record_budget_hit(conf, subject_public_key, scope)
  if conf.budget_enabled == false then
    return {
      enabled = false,
      count = 0,
      remaining = nil,
      over_soft = false,
      over_hard = false,
      refresh_eligible = true,
      penalty = 0,
      bonus = 0,
      reset_at = nil
    }
  end

  local window_seconds = conf.budget_window_seconds or 60
  local soft_limit = conf.budget_soft_limit or 30
  local hard_limit = conf.budget_hard_limit or 60
  local penalty_per_request = conf.budget_penalty_per_request_over_soft or 3
  local bonus_inside_budget = conf.budget_bonus_inside_budget or 5
  local bucket_start = math.floor(now() / window_seconds) * window_seconds
  local key = table.concat({ "auth", conf.origin, scope, subject_public_key, tostring(bucket_start) }, ":")
  local count

  if conf.budget_dict then
    conf.budget_dict:add(key, 0, window_seconds + 1)
    count = conf.budget_dict:incr(key, 1)
  else
    for candidate_key, entry in pairs(local_budget_counters) do
      if entry.expires_at <= now() then
        local_budget_counters[candidate_key] = nil
      end
    end
    local entry = local_budget_counters[key] or {
      count = 0,
      expires_at = bucket_start + window_seconds
    }
    entry.count = entry.count + 1
    local_budget_counters[key] = entry
    count = entry.count
  end

  local over_soft_by = math.max(0, count - soft_limit)
  return {
    enabled = true,
    count = count,
    window_seconds = window_seconds,
    soft_limit = soft_limit,
    hard_limit = hard_limit,
    remaining = math.max(0, soft_limit - count),
    reset_at = iso_time(bucket_start + window_seconds),
    over_soft = over_soft_by > 0,
    over_hard = count > hard_limit,
    refresh_eligible = over_soft_by == 0 and count == 1,
    penalty = over_soft_by * penalty_per_request,
    bonus = over_soft_by == 0 and bonus_inside_budget or 0
  }
end

local function evaluate_anonymous_budget(conf, request)
  if conf.anonymous_budget_enabled == false then
    return {
      enabled = false,
      mode = "challenge",
      allow = false,
      require_h418 = true,
      status = conf.status_code or 418,
      reason = "missing_presentation"
    }
  end

  local window_seconds = conf.anonymous_budget_window_seconds or 60
  local soft_limit = conf.anonymous_budget_soft_limit or 5
  local hard_limit = conf.anonymous_budget_hard_limit or 15
  local bucket_start = math.floor(now() / window_seconds) * window_seconds
  local anonymous_key = request.anonymous_key or "unknown"
  local key = table.concat({ "anon", conf.origin, request.scope, anonymous_key, tostring(bucket_start) }, ":")
  local count

  if conf.budget_dict then
    conf.budget_dict:add(key, 0, window_seconds + 1)
    count = conf.budget_dict:incr(key, 1)
  else
    local entry = local_budget_counters[key] or {
      count = 0,
      expires_at = bucket_start + window_seconds
    }
    entry.count = entry.count + 1
    local_budget_counters[key] = entry
    count = entry.count
  end

  local over_soft = count > soft_limit
  local over_hard = count > hard_limit
  local base = {
    enabled = true,
    count = count,
    window_seconds = window_seconds,
    soft_limit = soft_limit,
    hard_limit = hard_limit,
    remaining = math.max(0, soft_limit - count),
    reset_at = iso_time(bucket_start + window_seconds),
    over_soft = over_soft,
    over_hard = over_hard
  }

  if over_hard then
    base.mode = "block"
    base.allow = false
    base.require_h418 = false
    base.status = 429
    base.reason = "anonymous_budget_exceeded"
    return base
  end

  if over_soft then
    base.mode = "challenge"
    base.allow = false
    base.require_h418 = true
    base.status = conf.status_code or 418
    base.reason = "anonymous_budget_soft_limit"
    return base
  end

  base.mode = "observe"
  base.allow = true
  base.require_h418 = false
  base.status = 200
  base.reason = "anonymous_grace"
  return base
end

local function next_credential_score_with_budget(own_score, external_score, pow_difficulty, score, budget)
  if budget and budget.over_soft then
    local base = own_score > 0 and own_score or 10
    return math.max(10, math.min(base, base - budget.penalty))
  end
  if own_score > 0 and budget and not budget.refresh_eligible then
    return own_score
  end
  if own_score > 0 then
    return math.min(40, math.max(10, own_score + 5, math.floor(score * 0.65)))
  end
  return math.min(18, 10 + math.floor(external_score / 5) + (pow_difficulty >= 4 and 2 or 0))
end

function _M.issue_credential(conf, subject_public_key, scope, score, sequence)
  local issued_at = now()
  local credential = {
    h418_credential = _M.VERSION,
    credential_id = random_id("cred_"),
    issuer = {
      origin = conf.origin,
      key_id = conf.key_id,
      public_key_discovery = conf.origin .. "/.well-known/h418-policy"
    },
    subject = {
      public_key = subject_public_key
    },
    claims = {
      type = "recent_good_behavior",
      scope = scope,
      score = score,
      confidence = "medium",
      basis = { "passed_pow", "client_signature", "valid_credentials" }
    },
    lifecycle = {
      issued_at = iso_time(issued_at),
      expires_at = iso_time(issued_at + (conf.credential_ttl_seconds or 3600)),
      sequence = sequence
    },
    constraints = {
      audience = "any",
      requires_presentation_binding = true,
      max_score_contribution_external = 8
    }
  }
  credential.signature = assert(_M.sign_object(credential, conf.private_key))
  return credential
end

local function challenge_decision(conf, request, reason)
  local challenge = _M.create_challenge(conf, request)
  return {
    allowed = false,
    status = conf.status_code or 418,
    reason = reason,
    challenge = _M.encode_token(challenge)
  }
end

local function budget_exceeded_decision(conf, request, budget)
  local decision = challenge_decision(conf, request, "budget_exceeded")
  decision.status = 429
  decision.budget = budget
  return decision
end

function _M.decide(conf, request)
  if (not request.challenge) and (not request.presentation) and conf.anonymous_grace ~= false and not request.high_risk then
    local anonymous = evaluate_anonymous_budget(conf, request)
    if anonymous.allow then
      local challenge = _M.create_challenge(conf, request)
      return {
        allowed = true,
        observe = true,
        status = 200,
        mode = "observe",
        reason = anonymous.reason,
        anonymous_budget = anonymous,
        challenge = _M.encode_token(challenge)
      }
    end

    local decision = challenge_decision(conf, request, anonymous.reason)
    decision.status = anonymous.status
    decision.mode = anonymous.mode
    decision.anonymous_budget = anonymous
    return decision
  end

  if not request.challenge or not request.presentation then
    return challenge_decision(conf, request, "missing_presentation")
  end

  local challenge = _M.decode_token(request.challenge)
  local presentation = _M.decode_token(request.presentation)
  if not challenge or not presentation then
    return challenge_decision(conf, request, "malformed_presentation")
  end

  if challenge.method ~= request.method or challenge.path ~= request.path or challenge.scope ~= request.scope then
    return challenge_decision(conf, request, "challenge_context_mismatch")
  end

  if not _M.verify_object(challenge, conf.public_key) or not fresh(challenge) then
    return challenge_decision(conf, request, "invalid_challenge")
  end

  if presentation.challenge_id ~= challenge.challenge_id then
    return challenge_decision(conf, request, "challenge_id_mismatch")
  end

  if not verify_presentation_signature(presentation) then
    return challenge_decision(conf, request, "bad_client_signature")
  end

  local results = {}
  local top_n = conf.external_top_n or 3
  for i, credential in ipairs(presentation.credentials or {}) do
    if i > top_n then
      break
    end
    results[#results + 1] = verify_credential(conf, credential, presentation.subject_public_key, request.scope)
  end

  local own_score = 0
  local sequence = 0
  for _, result in ipairs(results) do
    if result.valid and result.own then
      own_score = math.max(own_score, result.score)
      sequence = math.max(sequence, result.sequence or 0)
    end
  end

  local external_score = score_external(results, conf)
  local budget = record_budget_hit(conf, presentation.subject_public_key, request.scope)
  if budget.over_hard then
    return budget_exceeded_decision(conf, request, budget)
  end

  local pow_difficulty = effective_pow_difficulty(request.fallback_pow_difficulty or 4, own_score, external_score, conf)
  local pow_ok = pow_difficulty == 0 or _M.verify_pow(challenge, presentation.subject_public_key, presentation.pow_nonce, pow_difficulty)
  local score = math.min(40, own_score) + external_score + (pow_ok and pow_difficulty > 0 and (15 + pow_difficulty) or 0) + 5 + budget.bonus - budget.penalty + (presentation.agent_intent and 5 or 0) - (request.high_risk and 20 or 0)

  if score < (request.min_score or 30) or not pow_ok then
    return challenge_decision(conf, request, "score_too_low")
  end

  local credential = _M.issue_credential(conf, presentation.subject_public_key, request.scope, next_credential_score_with_budget(own_score, external_score, pow_difficulty, score, budget), sequence + 1)
  return {
    allowed = true,
    status = 200,
    score = score,
    budget = budget,
    credential = _M.encode_token(credential)
  }
end

return _M
