## 2024-05-18 - [Context Leak in Goroutines]
**Vulnerability:** Goroutines spun up during request processing (e.g., in `persist/pgx_helper.go` for OTP issuance) were using `context.Background()`.
**Learning:** This breaks OpenTelemetry tracing and can lead to lost contexts. It's better to use `context.WithoutCancel(ctx)` to detach the cancellation signal but preserve the trace ID and other request-scoped values. Using `context.Background()` completely orphans the operation.
**Prevention:** Always use `context.WithoutCancel` when spinning up background tasks from an HTTP request context if you want them to survive the request's completion.

## 2026-03-17 - [Information Exposure / JSON Injection via err.Error()]
**Vulnerability:** Raw `err.Error()` values were being injected into JSON responses (`dpop_middleware.go`) and HTTP Headers (`httpx/middleware.go`). This allowed internal system errors (e.g., redis connection failures, database issues) to be leaked to the client. In JSON responses, this could also lead to JSON injection if the error message contained double quotes.
**Learning:** Directly embedding untrusted or system-generated strings like `err.Error()` in API responses violates the principle of failing securely and can expose internal architecture or cause malformed responses.
**Prevention:** Always log the actual error internally using structured logging (e.g., `log.Error().Err(err).Msg(...)`), and return generic, safe error descriptions to the client.
