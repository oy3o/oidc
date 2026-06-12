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

## 2024-06-12 - Prevent DPoP Validation Bypass and DoS
**Vulnerability:** DPoP validation in `dpop_middleware.go` extracted token claims using `jwt.ParseUnverified` instead of using cryptographically verified claims, potentially allowing claim modification if signature verification was separated. Additionally, `VerifyDPoPProof` did not enforce a length limit on the DPoP header, exposing the server to CPU/memory exhaustion DoS attacks during JWT parsing.
**Learning:** Claims extracted directly from the verified signature process should always be returned and used. Re-parsing using `ParseUnverified` negates the cryptographic integrity guarantees. Length limits on unbounded user input (like HTTP headers parsed as JWTs) are critical to prevent DoS.
**Prevention:** Always return the verified claims object directly from cryptographic validation functions (e.g., returning `*DPoPProof` from `VerifyDPoPProof`). Enforce strict length constraints (e.g., 4096 bytes) on cryptographic inputs before performing heavy parsing operations.
