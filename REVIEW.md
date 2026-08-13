# Review rules for this repository

Review rules on top of the reviewer's default focus. Three things:
which findings are blocking here, which classes to report that the
default focus would otherwise skip, and which are noise. The reasoning
behind the rules lives in `.github/copilot-instructions.md` (its
numbered focus items are cited below) and `CLAUDE.md`, which the
reviewer also receives.

## Always blocking

- **Presenting partial coverage as complete (§3).** A consumer of
  `DomainClient.fetch_activities()` that drops its `capped` return
  value, or does not OR it into the enclosing section's `capped` field.
  Every result section carries `capped` so an incompletely scanned
  window is never mistaken for "no findings".
- **Inverting the `GwsAuthError` / `GwsError` distinction (§4).** A
  domain-wide auth failure swallowed as if it were a per-probe error —
  an aggregation loop consuming a `GwsAuthError` result without
  re-raising it — or the reverse, a plain `GwsError` re-raised so one
  bad event name fails the whole domain's scan. Note that
  `_parallel_fetch` catching **both** and storing the exception as the
  task's result value is correct collection, not a finding; the
  distinction is applied where results are consumed.
- **Relaxing `is_external()`'s fail-safe default (§6).** An empty or
  malformed address must classify as external. For a security audit,
  "unknown" must not silently pass as internal — in that function or in
  any new classification path, including domain-scoped-grant handling.
- **Broadening an exposure or exclusion heuristic without equivalent
  evidence (§7).** `SELF_CREATION_GRANT_EVENTS`,
  `CANONICAL_VISIBILITY_EVENT` and `VISIBILITY_CHANGE_EVENTS` are
  scoped to named events, each justified inline by cited live-API data.
  Extending one of those sets, or adding a similar exclusion without
  either cited data or a stated invariant, can silently blind the
  tool's primary signal. Hold a new one to the same bar of evidence.
- **A secret or credential reaching a tool response or a log line
  (§8).** The parsed `GWSADM_CONFIG` contents — `service_account_file`
  paths, the impersonated `subject`, `customer_id` — or credential
  material.
- **A caught exception's raw `str(e)` / `repr(e)` returned to the MCP
  client without first confirming what that message can contain (§5).**
  `client.py`'s `_reports_service()` deliberately omits the text
  precisely because it may embed the key file path. One place in this
  file already made that call on purpose; a new one must not make the
  opposite call by accident.

## Report even though the default focus would not

- **A new tool's name and docstring.** The calling model decides
  whether and how to invoke a tool by reading them, so a vague name or
  a docstring omitting a parameter format the model would otherwise
  guess is a functional defect here — report it even though docstring
  accuracy is normally out of scope when reviewing code.
- **A new filter parameter passed into an API call without validation
  (§8)**, as advisory. Tool inputs arrive from an LLM acting on a
  user's behalf, so treat them as adversarial; `_select()`'s
  domain-name validation, which rejects an unconfigured domain with a
  clear error, is the existing pattern.
- **A diff that adds or changes a probe or tool and also touches
  `tests/` without covering the `capped=True` / `GwsError` /
  `GwsAuthError` paths (§9)**, as advisory. A gap there is a real
  coverage gap for this codebase. Judge it from the diff only: you
  receive changed files, so a pull request that leaves `tests/` alone
  may well be covered by tests you were not given.
- **A test that departs from this suite's conventions (§9)**, as
  advisory: tool functions are called directly
  (`server.login_audit(...)`), not through a `.fn` or `_call()`
  wrapper as some sibling repositories in this family do, and HTTP is
  faked through the hand-rolled `FakeDomainClient` injected by the
  `inject` fixture, not `respx` or a `googleapiclient` patch.

## Never report

- A finding that does nothing but restate one of the two gates CI
  already enforces: `ruff check .` and `ruff format --check .` both gate
  this repository, and
  `tests/test_smoke_probes.py` already fails the build for a
  registered tool with no probe spec. This covers those two and
  nothing further. It never applies to a rule listed under **Always
  blocking** above, even when the same diff happens to fail a test as
  well, and it does not cover that same file's tenant-specific-literal
  assertion — a leak reaching a public repository is worth
  catching twice.
- Suggestions to hand-build an MCP content envelope
  (`{"content": [...], "isError": ...}`) inside a tool handler. FastMCP
  wraps returned values already.
- Suggestions to *replace* `release-please.yml`'s
  `secrets.RELEASE_PLEASE_TOKEN` with `GITHUB_TOKEN`. Preferring the
  dedicated token is deliberate, because a `GITHUB_TOKEN`-authored
  release does not trigger the downstream `release` workflow. (The line
  falls back to `GITHUB_TOKEN` when the secret is unset, so a finding
  about the fallback arm itself is still fair game.)
- Anything about the sibling Box server. It is a separate repository
  and nothing here should be judged against it.
