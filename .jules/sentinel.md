## 2024-05-20 - Prevent Client ID Enumeration Timing Attacks
**Vulnerability:** The `AuthenticateClient` function returned early when `GetAndVerifyClient` failed, failing to perform the expensive password verification step. This allowed attackers to enumerate valid `client_id`s by observing the response time differences.
**Learning:** Returning early on authentication failures before completing time-consuming cryptographic operations causes observable side-channels. A "dummy" operation matching the actual validation operation is required.
**Prevention:** Perform a "dummy" hash comparison (e.g. `DummyCompare` matching bcrypt/argon2 execution times) whenever the client is not found or invalid, before returning the error. Ensure the dummy operation simulates the exact execution time.
