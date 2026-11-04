# Sigma conversion compatibility

The converter uses pySigma 2.0.1 and the Splunk backend 3.0.0 with an explicit
`SafePolicy` for collection parsing and the application-owned field mapping
pipeline. Regex must be compatible with RE2. Lookbehind and backreferences are
rejected; the application does not retry with Python regex or enable trusted
pipeline features. These constructs are not intrinsically invalid Sigma syntax,
but are outside this converter's chosen policy. Assessment parsing reports the
error, emits no query, and leaves conversion support false.

## November 2026 comparison

Compared with pySigma 1.5.1 / Splunk backend 2.1.0, all eight pinned catalog rules
converted successfully. Three queries were identical; five added parentheses
around OR terms and IN expressions. For these specific rule conditions, the
parentheses preserve grouping because Splunk search evaluates OR before AND.
See [Splunk's Boolean expression documentation](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.1/expressions-and-predicates/boolean-expressions-with-logical-operators).

Authored mapping, conjunction/disjunction, negation, ordinary regex, base64offset,
and unknown-selector probes produced identical outputs or errors. Lookbehind
and backreference probes converted on the old versions and raised
`SigmaRegularExpressionError` on the new versions. No pinned catalog rule uses
those constructs. This is an intentional conversion-support restriction.

The query snapshots retain source hashes and conditions; changes require review
against the original rule and Splunk semantics. Tests also cover explicit field
mapping, regex rejection and attribution/error handling in assessments.

This assessment covers generated queries and local tests. No live Splunk query
execution, telemetry correctness, or detection effectiveness is established.
The separate restricted synthetic Sigma matcher retains its existing limits.
