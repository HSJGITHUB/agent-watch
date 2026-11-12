# Changelog

## 0.1.4 (unreleased)

- Replace built-in confidential title terms with an empty-by-default denylist configurable through `AGENT_WATCH_TITLE_DENYLIST` and `--title-denylist-file`.
- Mask generic UNC hosts and shares, and generalize Windows user-home masking.
- Make Windows launch scripts portable and resolve the optional autostart helper relative to its own folder.
- Translate the UI, messages, comments, tests, and documentation to English; label Codex working folders as Task.
- Replace private examples with synthetic neutral fixtures; add MIT licensing and generated-file exclusions.

## 0.1.3 (2026-10-30)

Fixes from an independent adversarial code review:

- Recognize final Monitor notifications containing both status and event fields. Preserve background and workflow completion after notification eviction; close expired or orphaned Monitors appropriately.
- Restore expired runs on later activity, retain open workflow names, and hide unnamed runs until their names are recovered.
- Rotate background output checks fairly and bound completed-agent detail rereads by their completion-time file size.
- Strengthen secret masking for plural and suffixed keys, encoded keys, folded headers, shell continuations, YAML blocks, argument lists, and concatenated values while preserving ordinary paths and text.
- Improve overload responses by briefly draining request bytes before sending 503. Document remaining masking and retention limitations.

## 0.1.2 (2026-10-30)

Fixes from an independent adversarial code review:

- Harden quoted, multiline, nested, and encoded secret masking. Resolve titles by file order and propagate privacy through every owner before display filtering.
- Publish immutable detail snapshots, wake growing dormant Codex runs, and reset all affected state when source files are replaced.
- Respect pending background jobs during completion inference. Bound resident indexes and response sizes, retain omission counts, and prevent omitted items from being accessed through details.
- Schedule hot files fairly, distinguish ETags across restarts, cap concurrent handlers at 16, and enforce whole-request deadlines.
- Deduplicate repeated notifications and correct recovered descriptions and workflow counts.

## 0.1.1 (2026-10-30)

Fixes from an independent adversarial code review:

- Recover Codex model context and turn counts from large rollouts; handle streaming messages, asynchronous command output, and aborted turns.
- Improve elapsed time, unique tool counts, Monitor expiry, background lifecycle inference, and incomplete launch-record handling.
- Extend masking and identifier validation, propagate privacy to background owners, and apply security headers to error responses.
- Improve polling, response caps, resource metrics, stalled-item navigation, compact tables, detail ordering, loading states, omission labels, and theme behavior.

## 0.1.0 (initial release)

- Initial local, read-only dashboard for Claude sessions, subagents, workflows, background jobs, and Codex runs, with incremental scanning, masking, and browser detail views.
