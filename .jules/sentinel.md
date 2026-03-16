## 2024-05-18 - [Context Leak in Goroutines]
**Vulnerability:** Goroutines spun up during request processing (e.g., in `persist/pgx_helper.go` for OTP issuance) were using `context.Background()`.
**Learning:** This breaks OpenTelemetry tracing and can lead to lost contexts. It's better to use `context.WithoutCancel(ctx)` to detach the cancellation signal but preserve the trace ID and other request-scoped values. Using `context.Background()` completely orphans the operation.
**Prevention:** Always use `context.WithoutCancel` when spinning up background tasks from an HTTP request context if you want them to survive the request's completion.

## 2024-05-18 - [Prevent Information Exposure via Error Messages]
**Vulnerability:** Internal errors (such as those from token parsing, DPoP validation, or underlying database connections) were being concatenated directly into `WWW-Authenticate` headers and JSON error responses via `err.Error()`.
**Learning:** This can lead to Information Exposure (CWE-209), where sensitive internal details (stack traces, internal IP addresses, or library structures) are leaked to unauthenticated users.
**Prevention:** Always sanitize error messages returned to clients. Use generic error descriptions like "Invalid or missing token" in the response, and log the detailed `err` internally using the logging framework for debugging purposes.
