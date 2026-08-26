# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them
privately through GitHub's [private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or by e-mail to the maintainer at
<bisratlike@gmail.com> with "go-dev-auth security" in the subject.

Include a description of the issue, the affected version, and a
reproduction if you have one. Expect an acknowledgement within a few
days and an assessment shortly after. Good-faith research is welcome;
reports will not be met with legal threats.

## Supported versions

The latest release receives fixes. Once 1.0 ships, the latest minor
release of the current major version receives fixes.

## Security model

The attacker model, the design decisions that follow from it, and how
each claim is verified are documented in
[docs/security-model.md](../docs/security-model.md). The summary below
is what the library guarantees, and what it expects from you.

### Credentials
- Passwords are hashed with scrypt (N=16384, r=16, p=1), the same
  parameters and `salt:key` encoding better-auth uses. Verification is
  constant-time.
- Hashing is deliberately expensive (~50 ms, ~32 MiB per attempt).
  Concurrency is capped so peak memory is bounded, and requests that
  cannot get a slot are shed with 503 rather than queueing.
- Sign-in burns equivalent time when no account exists, so response
  timing does not reveal whether an address is registered.

### Sessions
- 32 bytes of entropy per token; cookies are HMAC-SHA256 signed with
  domain separation and receive the `__Secure-` prefix over HTTPS.
- Raw tokens never appear in API responses.
- The optional cookie cache carries an absolute revalidation deadline
  that is never extended from cached data.

### One-time tokens
Password reset, email verification, magic links, account deletion and
OAuth state are stored as SHA-256 digests and claimed atomically, so a
concurrent replay cannot redeem the same token twice, and read access to
the database yields no usable links.

### OAuth and OIDC
- Authorization uses PKCE (S256); state is single-use, expiring, bound
  to the browser by cookie and pinned to the issuing provider.
- Automatic account linking requires both a provider-asserted verified
  email **and** that the provider is listed in
  `Account.AccountLinking.TrustedProviders`.
- ID tokens are verified against the issuer's JWKS with issuer,
  audience, `azp`, expiry and nonce checks.

### Authorization
- Fields that decide access (`role`, `banned`, `twoFactorEnabled`) are
  never writable from a request body.
- `SignInGuard` runs on every sign-in path; `SessionGuard` runs on every
  request, including API-key authenticated ones.
- Values of an unexpected type in a security-deciding column fail
  closed.

## What the library expects from you

- **Set a strong `Secret`** (32+ random bytes) and keep it out of source
  control. It signs cookies and encrypts secrets at rest.
- **Set `BaseURL` correctly.** It determines cookie security, the
  trusted-origin set and redirect validation.
- **Serve over HTTPS** in production.
- **Keep rate limiting enabled.** It is load-bearing for both
  brute-force resistance and availability. Use a shared
  `RateLimit.Storage` when running more than one instance.
- **Create the schema and its indexes.** Uniqueness of emails and
  session tokens is enforced by the database, not by application code.
- **Run `CleanupExpired` periodically**, or expired tokens accumulate.
- **Do not enable `TrustProxyHeaders`** unless a proxy you control
  strips client-supplied `X-Forwarded-For`; otherwise a client can
  choose its own rate-limit bucket.
