insert into public.allowed_tools (name, allowed_params, active) values
  (
    'nuclei',
    '{"tags_allowlist": ["cve", "misconfig", "exposure", "tech"], "tags_denylist": ["dos", "intrusive", "fuzz", "bruteforce"], "rate_limit": 50, "timeout_s": 600}'::jsonb,
    true
  ),
  (
    'testssl',
    '{"timeout_s": 300}'::jsonb,
    true
  ),
  (
    'headers',
    '{"timeout_s": 30}'::jsonb,
    true
  )
on conflict (name) do nothing;
