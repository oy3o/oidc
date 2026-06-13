## 2024-05-18 - [Context Leak in Goroutines]
**Vulnerability:** Goroutines spun up during request processing (e.g., in `persist/pgx_helper.go` for OTP issuance) were using `context.Background()`.
**Learning:** This breaks OpenTelemetry tracing and can lead to lost contexts. It's better to use `context.WithoutCancel(ctx)` to detach the cancellation signal but preserve the trace ID and other request-scoped values. Using `context.Background()` completely orphans the operation.
**Prevention:** Always use `context.WithoutCancel` when spinning up background tasks from an HTTP request context if you want them to survive the request's completion.

## 2026-03-18 - [SQL Wildcard Injection / DoS via ILIKE]
**Vulnerability:** User input was directly concatenated with `%` characters in Squirrel's `ILike` queries without escaping special wildcard characters (`\`, `%`, `_`).
**Learning:** This allowed an attacker to input arbitrary wildcards, potentially bypassing application logic or causing excessive load on the database via unanchored search strings. The correct approach is to escape these characters before adding them to the database pattern.
**Prevention:** Always escape user-provided input strings before concatenating them with `%` or `_` for use in `LIKE`/`ILIKE` clauses, using `strings.ReplaceAll` to escape `\`, `%`, and `_` characters.

## 2026-03-20 - [Base64 Decoding Unhandled Error and Token Length Limits]
**Vulnerability:** When decoding Base64 strings in `ValidateStructuredRefreshToken`, `base64.RawURLEncoding.DecodeString` errors were ignored. This could cause invalid data to be passed to MAC verification and could also open vectors for CPU/memory DoS via excessively large inputs.
**Learning:** Always handle errors from Base64 decoding to prevent operating on corrupted, empty, or nil byte slices which could lead to panics or authentication bypass. Furthermore, cryptographic and parsing operations (like hash checking or JSON decoding) should not process unbounded input lengths to prevent resource exhaustion.
**Prevention:** Enforce input length bounds (e.g., maximum token length) *before* decoding strings and *always* check for and gracefully handle `err` returned by `DecodeString` routines.
## 2024-06-13 - [JWT Validation Bypass in DPoP Proof Parsing]
**Vulnerability:** The `DPoPMiddleware` function was using `jwt.ParseUnverified` to extract the `ATH` claim from the DPoP header *after* the header had been verified by `VerifyDPoPProof`. While `VerifyDPoPProof` correctly validated the signature, re-parsing the header with `ParseUnverified` to extract claims means those extracted claims are not cryptographically guaranteed to be the ones that were just validated, potentially allowing an attacker to supply a token where the parsed claims differ from the validated ones (e.g. if the token structure was somehow manipulated between the two parsing steps, though unlikely, it's a bad pattern) or simply redundant and insecure parsing practice. Furthermore, `ParseUnverified` can be risky if its results are trusted without context.
**Learning:** Always use the claims returned from the strict cryptographic verification process (e.g., `jwt.ParseWithClaims`) rather than re-parsing a token unverified to extract fields. If a verification function validates a token, it should return the validated claims object so callers don't need to re-parse.
**Prevention:** Modify `VerifyDPoPProof` to return the validated `*DPoPProof` claims alongside the JKT. Use these returned claims directly in the middleware instead of calling `ParseUnverified`.
