# Go style

Two gates at write time, in order. **Necessity**: a source file is not a story board — every comment must answer "what could the next editor get wrong HERE?"; correct-but-idle narrative belongs nowhere. **The rot test**: can this sentence become false without this file changing? A claim about the code beside it cannot drift; a claim about anything outside it will.

## Comments

- **Comment why, never what** — the RFC 6749 caveat in `oauth2ex.go` and the alg-confusion link inside the JWT keyfunc in `main.go` are the register; a sentence restating the statement below it fails Necessity.
- **Doc-comment every exported symbol and every non-obvious unexported one** — `config.go` sets the density.
- **Introduce an explained block inside a function with a bare `//` separator line above the comment** — that is the house shape in `main.go`; keep it when you add a block.
- **State decisions and invariants, never status or schedules** — "deliberately dropped" survives; "TODO next release" rots the moment the work moves.
- **A comment naming an external library or an upstream file is a rot candidate** — re-read such a comment before trusting it and before writing another.
- **A test's comment is a claim about the assertions below it** — re-read it when the fix lands, or a comment describing the world the test just disproved ships with the green run.

## Layout

- **Everything is flat `package main` at the repo root** — a new concern is a new root-level `.go` file with a matching `_test.go` sibling, the way `config.go` and `utils.go` were split out of `main.go`.
- **Never add a subpackage or `internal/` on your own initiative** — the tests are internal and call unexported identifiers, so moving a symbol out of `package main` breaks them at compile time.
- **Only `main.go` may call `log.Fatal`, `os.Exit`, or `panic`** — `config.go`, `oauth2ex.go` and `utils.go` return errors and never terminate, because the exit codes are the PAM interface and belong to the one file that owns it.
- **Moving code out of `main.go` strips the exit with it** — the extracted function returns an error and the caller in `main.go` decides the code; a refactor that carries a `log.Fatal` into a library file breaks the split.
- **Export only the testable seams** — `Config`, `ConfigError`, `ErrMissingRequired`, `LoadConfigFromFile`, `LoadConfigFromReader`, `Validate` are exported and everything else is lowercase; in `package main` the case means nothing to the compiler and everything to the reader, so follow it anyway.
- **Make an untestable function testable by adding a `*WithError` sibling and leaving the old name as a thin wrapper** — `loadConfig` keeps the `log.Fatal` and delegates to `loadConfigWithError`, and the wrapper says so in its doc comment.

## Errors

- **A new failure mode gets a typed error, not a bare `errors.New` at the call site** — follow `ConfigError`: an `Op`/`Path`/`Err` struct, `Error()` built with `fmt.Sprintf`, an `Unwrap()`, plus a package-level `Err*` sentinel wrapped with `%w` as `ErrMissingRequired` is.
- **New codecs keep `utils.go`'s shape** — named result parameters, a zero value instead of an error, and the caller detecting the empty/nil result as `genUsername` does.

## Logging

- **Every log line on the authentication path passes `sid` as its first argument** — the correlation prefix is built once per attempt in `main.go` and is what ties an operator's grep to one login.
- **Flatten multi-line errors with `strings.ReplaceAll(err.Error(), "\n", ". ")` before logging** — one authentication attempt must stay one log line.
- **Never reword a log message the docs tell operators to grep for** — `docs/content/install.md` sends them looking for `"...(test1) Authentication succeeded"`, so that text is an interface, not prose.
- **Use the stdlib `log` package** — no structured-logging dependency.

## Dependencies

- **Reach for the stdlib first** — TOTP is hand-rolled on `crypto/hmac` + `crypto/sha1` and the OAuth2 password grant is forked into `oauth2ex.go` rather than pulling in wrappers.
- **A new dependency needs justification** — the graph is flat, with no indirect entries in `go.sum`; keep it that way.
- **Forked code keeps its provenance header and upstream's error prefixes** — `oauth2ex.go` opens with "Heavily tailored from golang.org/x/oauth2/oauth2.go" and still emits `oauth2: ...`, which is how the next reader knows to diff against upstream before editing.

## Tests

- **Tests are internal `package main`** — they call `genUsername`, `doTokenRoundTrip`, `tokenJSON` and friends directly, and Go's external `package main_test` default will not compile against them.
- **Put a test in the `_test.go` beside the file it covers** — source and test pair 1:1; never open a second test file for an existing source file.
- **Name new tests `TestFuncName_Scenario`** — leave the legacy bare names (`TestUsername`, `TestOTP`, `TestBase32`, `TestEncryptDecrypt`, `TestAscii85`) as they are.
- **Stdlib `testing` only** — no testify, no gomock; the module has zero test-only dependencies and adding one moves `go.mod` and `go.sum`.
- **Prefer one focused test function per scenario with an inline `if got != want { t.Errorf(...) }`** over a table; when the cases are genuinely uniform, wrap each in `t.Run` as `oauth2ex_test.go` does rather than copying the bare loops in `main_test.go`.
- **Phrase assertions `got = X; want Y`** — `t.Fatalf` for setup and precondition failures, `t.Errorf` for value mismatches so one run reports every deviation.
- **Fake HTTP with `httptest.NewServer` plus `defer server.Close()`, injected through `oauth2.Endpoint{TokenURL: server.URL}`** — there is no RoundTripper mock and no shared server helper; each test builds its own handler.
- **Assert the outgoing request inside the handler, after `r.ParseForm()`** — check `PostForm` and `BasicAuth` there; encode success bodies with the production `tokenJSON` struct and set `Content-Type` explicitly whenever the branch under test is not JSON.
- **Config fixtures are inline TOML `const`s at the top of `config_test.go`, fed to `LoadConfigFromReader`** — that seam exists so tests avoid the filesystem; there is no `testdata/` tree, and `t.TempDir()` + `os.WriteFile` is only for testing `LoadConfigFromFile` itself.
- **Reuse the existing fixed secrets** — the `scmi` XOR key, the `JBSWY3DPEHPK3PXP` TOTP secret, `test-client`/`test-secret`; never generate one and never read one from the environment.
- **Keep tests deterministic** — pass the timestamp into `calculateOtpToken` instead of calling `time.Now()`, and never assert on map-iteration order.
- **Assert error identity, not error text** — `errors.As`/`errors.Is` for `*ConfigError` and `ErrMissingRequired`, a type assertion for `*retrieveError` (it has no `Unwrap`), and check `ConfigError.Op` rather than the formatted message.
- **Never add a test that cannot fail** — the existing `t.Log`-only tests document behaviour rather than asserting it; leave them, do not imitate them.

## Traps

- **The generated width and the parsed width are two unrelated literals that happen to agree** — the `digits` const fixes what `calculateOtpToken` GENERATES for the hardcoded-MFA path, while `main()`'s `^(.+)(\d{6})$` fixes what is split off a typed password; changing one leaves the other at 6.
- **`PAM_USER` reaches the log line unsanitised through the `sid` prefix** — `main.go` flattens newlines out of ERROR text but not out of the username, so a crafted username can still forge log structure; gosec's G706 is suppressed in `.golangci.yml` pointing here, not fixed.
- **`(*Config).Validate()` is never called from production code** — `main()` runs straight from `loadConfig()` into use, so a check added to `Validate()` is not enforced; an empty `xor-key` instead reaches `encryptDecrypt` and panics on divide-by-zero on every authentication.
- **`RedirectUri` and `AccessTokenSigningMethod` are parsed and never read** — the accepted signing algorithm is taken from the token's own `alg` header, so "wiring up" the config field changes security behaviour for every existing deployment.
- **An `enc`-use JWK must never enter the verification pool** — Keycloak publishes its RSA-OAEP key at the same endpoint as its signing key, and `parseJWKS` skips it; a decode path that stopped honouring `use` would widen what can sign a token.
- **`config.Scope` is two things at once** — the OAuth2 `scope` request parameter AND the JWT claim key searched for roles; changing it to fix a token request silently changes authorization.
- **No `Version` or `Build` variable exists in any `.go` file** — the Makefile's `-X main.Version` stamps nothing and the linker ignores it without a word, so a `--version` flag built on it prints empty; declaring the variables is not enough either, because `build_all` never passes `LDFLAGS`.
- **`main()` is uncovered and the OTP pattern is built inside it** — a test for OTP splitting means extracting the pattern builder into a testable function first; without that seam there is no way to test it.
