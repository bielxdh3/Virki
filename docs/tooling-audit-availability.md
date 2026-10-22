# Tooling audit availability and fail-closed verification

The isolated Linux runner performs **two independent checks** after `npm ci`:
the locked Prisma tooling versions and a live `npm audit --package-lock-only
--json` security report. Installing packages successfully does not prove that
the npm registry's **audit endpoint** was reachable. The audit gate must never
be passed from an installation success, a fixture, a cached/partial result, or
an unverified response.

## Decision boundary

`scripts/tooling-audit-policy.mjs` accepts only an actual npm audit report
version 2 containing a vulnerability map and complete nonnegative integer
severity counts. A valid report with vulnerabilities still fails the policy;
`npm audit` exit code 1 is the expected CLI result in that case. Unexpected
command exit codes, an empty or malformed response, a non-v2 report and npm's
`{"error":{...}}` registry/transport response all **fail closed**, separately
classified as `status=unavailable`. No raw npm error message, report package
names, registry URL, token or stderr is printed by the gate. Valid findings
are reported using fixed error messages and aggregate counts only.

The audit process has a 45-second maximum wall-clock runtime with npm's
`--fetch-retries=0 --fetch-timeout=25000` arguments. There is no policy
exemption, cached success, automatic retry or `--audit=false` fallback. The
former environment-selected `VIRKI_TOOLING_AUDIT_JSON` override is **not**
accepted by the production policy command. Offline/adversarial JSON cases
exercise exported pure functions in deterministic unit tests only.

The isolated runner redirects **the entire compound tooling stage** to its
private file before displaying a bounded log tail. Previously `A && B > file`
redirected only `B`; a failing audit in `A` left the log missing, producing
a misleading `tail: cannot open` message instead of the gate result.

## Safe operator interpretation

An `unavailable` status means the audit result was **not established**. It is
neither a passing security review nor evidence of vulnerabilities. An ordinary
`failed` status on a complete report means the gate evaluated the real report
and found vulnerabilities, pinned dependency drift, or another policy failure.
Do not push, deploy or accept a release on either outcome. Restore registry
connectivity and rerun the exact isolated test stage to obtain a fresh report.
Never edit the lockfile solely to force a reported zero count.

A disposable local Docker probe on 2026-10-22, using the checked-in package
lockfile with a pinned Node 22 image and temporary per-container npm cache,
received a real version-2 report (exit 0, reported vulnerability total 0).
That **only** establishes that the audit endpoint answered during that probe;
it does not establish what caused the earlier `auditReportVersion=null` run or
replace the audit and version checks inside a future isolated release runner.
