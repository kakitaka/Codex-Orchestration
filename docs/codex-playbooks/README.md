# Codex playbooks

Playbooks are small Git-backed indexes, not prompts. Each JSON document may store:

- repository-relative source path;
- current Git blob ID;
- symbol or heading name;
- a short operational action/failure label;
- validation command name without captured output.

Never store source excerpts, raw prompts/conversations, command logs, credentials, session IDs, absolute paths, telemetry events, or LLM summaries.

Run `python scripts/check_playbook_staleness.py` before handoff. A source blob change invalidates its entry and requires a focused human update. The checker performs no model call.
