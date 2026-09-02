-- D-Gen policy pack (Lua) — API v1
--
-- This file is part of the *control-plane*.
-- Keep it safe to share: DO NOT embed raw bypass arguments/strategies here.
--
-- DGen.exe provides:
--   - global: DGEN_POLICY_API_VERSION
--   - function: dgen_log(...)
--
-- Engine calls:
--   dgen_policy(ctx)
-- once during autopick initialization.
--
-- ctx (table) fields:
--   api_version, net_key, mode
--   link ("wifi"|"ethernet"), link_is_ethernet (bool)
--   want_twitter (bool)
--   timeout_ms, warmup_ms, deadline_ms
--   retry_budget
--   phase2_timeout_ms, phase2_warmup_ms
--   fail_count (int, repeated core-mode failures for this net_key)
--   last_fail (string, one of: dns/tls/connect/timeout/http/other; may be empty)
--
-- Return value:
--   - nil: no overrides (default)
--   - table with any of:
--       deadline_ms, retry_budget, phase2_timeout_ms, phase2_warmup_ms

function dgen_policy(ctx)
  -- Default: keep engine behavior unchanged unless we see repeated failures on this net.
  if type(ctx) ~= 'table' then return nil end

  local fc = tonumber(ctx.fail_count or 0) or 0
  if fc < 2 then
    return nil
  end

  -- Primary target: Wi‑Fi networks that repeatedly fail in core-mode autopick.
  if ctx.link ~= 'wifi' then return nil end
  if ctx.want_twitter then return nil end

  local deadline = tonumber(ctx.deadline_ms or 0) or 0
  local retry = tonumber(ctx.retry_budget or 0) or 0
  local p2t = tonumber(ctx.phase2_timeout_ms or 0) or 0
  local p2w = tonumber(ctx.phase2_warmup_ms or 0) or 0

  -- Safe caps: give more time/budget, but don't turn autopick into a "hang".
  -- IMPORTANT: never *reduce* budgets that were already raised by the engine.
  local lf = tostring(ctx.last_fail or '')

  local min_deadline = 60000
  if lf == 'timeout' or lf == 'connect' then
    min_deadline = 90000
  end
  local new_deadline = math.max(deadline, min_deadline)
  if new_deadline > 120000 then new_deadline = 120000 end

  local new_retry = math.max(retry, 24)
  if new_retry > 40 then new_retry = 40 end

  local new_p2t = math.max(p2t, 3500)
  if new_p2t > 6000 then new_p2t = 6000 end

  local new_p2w = math.max(p2w, 1200)
  if new_p2w > 2500 then new_p2w = 2500 end

  if new_deadline == deadline and new_retry == retry and new_p2t == p2t and new_p2w == p2w then
    return nil
  end

  dgen_log(
    'policy: escalate budgets',
    'link=' .. tostring(ctx.link),
    'fail_count=' .. tostring(fc),
    'last_fail=' .. lf,
    'deadline_ms=' .. tostring(deadline) .. '->' .. tostring(new_deadline),
    'retry_budget=' .. tostring(retry) .. '->' .. tostring(new_retry),
    'phase2_timeout_ms=' .. tostring(p2t) .. '->' .. tostring(new_p2t),
    'phase2_warmup_ms=' .. tostring(p2w) .. '->' .. tostring(new_p2w)
  )

  return {
    deadline_ms = new_deadline,
    retry_budget = new_retry,
    phase2_timeout_ms = new_p2t,
    phase2_warmup_ms = new_p2w,
  }
end
