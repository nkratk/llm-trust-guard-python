# Results — v0.13.0 (ToolChainValidator parameter injection + structured document injection)

- **Date:** 2026-07-02
- **Library version:** 0.13.0 (PyPI) / 4.24.0 (npm)
- **Driven by:** 48% POC miss-rate analysis across 1134 threat scenarios

## Why

Same as TS v4.24.0 — two concentrated miss clusters identified by corpus analysis:
1. `ToolChainValidator` 0% detection (220 misses) — no parameter content scanning
2. `ExternalDataGuard` + `ToolResultGuard` 3.5%/5.9% (738 combined misses) — no
   structured document injection patterns

## Changes

- **`ToolChainValidator`**: `_OS_CMD_RE` class-level regex; scans `tool_name` +
  `all_tools_in_request`; new violation `OS_COMMAND_INJECTION_IN_TOOL_PARAMETER`;
  config `detect_parameter_injection` (default `True`).
- **`ExternalDataGuard`**: 10 new patterns — xxe_entity, doctype_entity,
  path_traversal, office_xml_script, rtf_ole_object, html_comment_directive,
  embedded_tool_call, langchain_gadget, email_agent_directive.
- **`ToolResultGuard`**: 7 matching patterns — same surface, critical severity.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 844 | **852** (+8) |
| npm vitest | 763 | **779** (+16) |

WildChat FPR: 493/10,000 (unchanged). `bash scripts/verify.sh` — all gates green.
