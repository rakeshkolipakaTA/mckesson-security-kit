"""Tool policy for the support-bot agent (default deny: python_exec and sql_query are intentionally absent)."""
POLICY = {"agents": {"support-bot": {"allow_roles": ["user", "admin"], "tools": {
    "read_file":      {"scopes": ["files:read"], "args": {"path": {"max_len": 200}}},
    "http_fetch":     {"scopes": ["net:fetch"], "args": {"url": {"max_len": 500, "regex": r"https://api\.example\.com/.*"}}},
    "delete_records": {"scopes": ["data:delete"], "approval": True, "args": {"table": {"enum": ["tmp_cache"]}}},
    "send_email":     {"scopes": ["mail:send"], "approval": True, "args": {"to": {"regex": r"[^@\s]+@example\.com"}, "body": {"max_len": 2000}}},
}}}}
