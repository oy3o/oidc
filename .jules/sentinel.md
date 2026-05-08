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
## 2026-03-21 - [Timing Attack via Empty Client Secret]
**Vulnerability:** In functions handling client authentication (`AuthenticateClient`, `ExchangeClientCredentials`, and `PasswordGrant`), if `ClientSecret` was empty, the code immediately returned an error (`ErrInvalidClient` or `ErrInvalidRequest`).
**Learning:** Returning early on an empty client secret skips the actual hashing and comparison of the secret. This causes the function to execute significantly faster than if a non-empty secret were provided and validated. Attackers could exploit this time difference (timing attack) to enumerate valid client IDs, because an invalid client ID might take a different amount of time to reject compared to a valid client ID with an empty secret. To mitigate this, a dummy comparison `hasher.DummyCompare(ctx)` must be executed whenever a real hash comparison is skipped.
**Prevention:** Always ensure that authorization and token exchange endpoints do not return early on empty client secrets without performing dummy operations (e.g., `Hasher.DummyCompare`) to normalize response times and prevent client ID enumeration attacks.
