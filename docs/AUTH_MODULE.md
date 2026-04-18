# Auth Module

Modular authentication extension for the TemplateBaseSicurezza framework.
Provides three independent, deactivable mechanisms:

- **JWT (HS256)** — stateless API access tokens with refresh-rotation and DB blacklist
- **Magic Link** — passwordless login via email (single-use, hashed in DB)
- **TOTP 2FA** — RFC 6238 (Google Authenticator compatible)

All flows reuse the framework primitives: `SECURE_ACCESS` guard, `Logger` (GDPR
pseudonymisation), `RateLimiter` (static API), prepared statements, Zero-Trust
queries, `Config` helper with dotted-key lookup.

---

## Configuration

### Constants — `config/constants.php`

```php
define('JWT_ALGO', 'HS256');
define('JWT_ACCESS_EXPIRY', 900);          // 15 minutes
define('JWT_REFRESH_EXPIRY', 604800);      // 7 days
define('JWT_ISSUER', APP_NAME);
define('JWT_BLACKLIST_DRIVER', 'database'); // only 'database' supported

define('MAGIC_LINK_ENABLED', true);
define('MAGIC_LINK_EXPIRY', 600);          // 10 minutes

define('TOTP_ENABLED', true);
define('TOTP_ISSUER', APP_NAME);
define('TOTP_DIGITS', 6);
define('TOTP_PERIOD', 30);
define('TOTP_ALGO', 'sha1');
```

Disable a feature by setting the matching `*_ENABLED` flag to `false`.
Endpoints return `404 feature_disabled`.

### Secrets — `config/config.php`

```php
'jwt' => [
    'secret_key' => '...',  // 32+ random chars — bin2hex(random_bytes(32))
],
'magic_link' => [
    'secret_key' => '...',
],
'app' => [
    'base_url' => 'https://example.com',
],
'mail' => [
    'from' => ['address' => 'no-reply@example.com', 'name' => 'App'],
    'smtp' => [
        'host' => 'smtp.example.com',
        'port' => 587,
        'username' => 'no-reply@example.com',
        'password' => '...',
        'encryption' => 'tls',   // 'tls' | 'ssl' | ''
    ],
],
```

---

## Runtime helpers

| Helper | File | Purpose |
|--------|------|---------|
| `Config::get('jwt.secret_key', $default)` | `system/Config.php` | read-only dotted access to `$GLOBALS['config']` |
| `Config::require('jwt.secret_key')` | `system/Config.php` | same but throws if missing (also in production) |
| `Config::has('mail.smtp.host')` | `system/Config.php` | existence probe |
| `RateLimiter::throttle($key, $max, $window)` | `system/RateLimiter.php` | **static**; returns false when the window cap is reached |
| `RateLimiter::reset($key)` | same | zero the counter after a successful auth |

**Important:** `RateLimiter` is fully static. Do **not** write `new RateLimiter(...)`
— the old instance API has been removed. All controllers in the auth module use
the static form:

```php
$key = 'api_login_' . hash('sha256', $ip);
if (!RateLimiter::throttle($key, 10, 300)) { /* 429 */ }
// ...on success:
RateLimiter::reset($key);
```

---

## PHPMailer

The magic-link controller uses `system/Mailer.php` which lazy-loads PHPMailer
from:

```
system/lib/PHPMailer/src/{Exception,PHPMailer,SMTP}.php
```

If the files are missing `Mailer::send()` throws `RuntimeException` with the
exact missing paths. See `system/lib/PHPMailer/README.md` for the download
procedure, and `INSTALL.md §5`.

In `APP_ENV='development'` the Mailer enables `SMTPDebug=2` and the SMTP
transcript is written to `logs/debug/` via `Logger::debug`. Any send failure is
re-thrown in dev (loud-debug); in production it returns `false` and logs.

---

## Database

Run `database/auth_module.sql`. It creates:

| Table          | Purpose                            |
|----------------|------------------------------------|
| `refresh_tokens` | rotation + revocation log        |
| `jwt_blacklist`  | revoked access-token JTIs        |
| `magic_links`    | single-use passwordless tokens   |

It also adds two columns to `users`: `totp_secret`, `totp_enabled`.

---

## API Endpoints

All endpoints accept and return JSON. Errors follow the shape
`{"error": "<code>"}` with the appropriate HTTP status.

In `APP_ENV='development'` error responses coming from an uncaught exception
additionally include `exception`, `message`, `file`, `line`, `trace` — the
enrichment is applied by either `BaseController::jsonError()` (when the
controller catches explicitly) or by the global handler in `public/index.php`.

### JWT

| Method | Path                | Auth   | Body / Notes |
|--------|---------------------|--------|--------------|
| POST   | `/api/auth/login`   | none   | `{email, password, totp?}` — 10 req / 5 min / IP |
| POST   | `/api/auth/refresh` | none   | `{refresh_token}` — rotates JTI; reuse revokes ALL user tokens |
| POST   | `/api/auth/logout`  | Bearer | blacklists current JTI + revokes all user refresh tokens |
| GET    | `/api/auth/me`      | Bearer | `{user: {id, email, totp_enabled}}` |

Successful login/refresh response:

```json
{
  "access_token":  "eyJ...",
  "refresh_token": "eyJ...",
  "token_type":    "Bearer",
  "expires_in":    900
}
```

### Magic Link

| Method   | Path                | Notes |
|----------|---------------------|-------|
| POST     | `/api/magic/request`| `{email}` — 5 req / 10 min / IP. Sempre 200 (no enumeration) |
| POST/GET | `/api/magic/verify` | `{token}` o `?token=...`. Ritorna le stesse token pair di login |

### 2FA TOTP

| Method | Path              | Auth   | Body     |
|--------|-------------------|--------|----------|
| POST   | `/api/2fa/setup`  | Bearer | —        |
| POST   | `/api/2fa/enable` | Bearer | `{code}` |
| POST   | `/api/2fa/disable`| Bearer | `{code}` |
| GET    | `/api/2fa/status` | Bearer | —        |

`setup` returns the base32 `secret` and an `otpauth://` `provisioning_uri`
for QR-code generation client-side.

---

## Security model

- **Access token**: short TTL (15 min), HS256 signed, `iss`/`exp`/`nbf`/`jti` claims.
  Signing key is resolved via `Config::require('jwt.secret_key')` — a missing or
  <32-char key aborts with `RuntimeException` in **both** environments.
- **Refresh token**: long TTL (7 days), `typ=refresh`, JTI persisted in
  `refresh_tokens`. Rotation on every refresh; **reuse of a revoked JTI revokes
  all user tokens** (`RefreshTokenModel::revokeAllForUser`).
- **Blacklist**: revoked access JTIs live in `jwt_blacklist`.
  `JwtBlacklistModel::isBlacklisted()` is **fail-closed** in production: a DB
  outage makes the helper return `true`, so a revoked token cannot slip through.
  In development the exception is re-thrown instead (loud-debug).
- **Magic link**: 32 random bytes, sha256-hashed in DB, single-use enforced
  atomically by `UPDATE ... WHERE used_at IS NULL`. Client IP stored as sha256.
- **TOTP**: RFC 6238, Google Authenticator compatible. Window ±1 step (≈90s)
  tolerates clock skew. Secret stored in DB; **never** logged.
- **Rate limiting**: `/api/auth/login` 10 / 5min / IP;
  `/api/magic/request` 5 / 10min / IP. Implemented with `RateLimiter::throttle`.
- **Logging**: all failures via `Logger::security` with `gdpr_sensitive=1`
  so IPs/emails are masked/hashed automatically.

---

## Error handling & debug

The auth-module classes follow a **loud-debug / fail-closed** policy:

| Layer | Success path | Failure in `development` | Failure in `production` |
|-------|-------------|--------------------------|-------------------------|
| `Mailer::send`           | `true` + `Logger::debug` | exception re-thrown | `false` + `Logger::error` |
| `JwtBlacklistModel::isBlacklisted` | returns `bool` | exception re-thrown | returns `true` (fail-closed) |
| `JwtBlacklistModel::add/purge` | — | exception re-thrown | logged, call returns silently |
| `UserModel::*` (DB ops) | normal return | exception re-thrown via `dbCatch` | logged, call returns safe default |
| `Jwt::secret()` | secret string | — | **throws** (also in prod) if missing/short |
| `public/index.php` global catch | — | JSON/HTML includes file/line/trace | generic 500 message |

The global catch in `public/index.php` decides JSON vs HTML by looking at
`/api/*` in the request URI. The JSON body fields in dev are:

```json
{
  "error":     "internal_error",
  "exception": "RuntimeException",
  "message":   "...",
  "file":      "/.../app/Models/UserModel.php",
  "line":      112,
  "trace":     ["#0 ...", "#1 ..."]
}
```

---

## Disabling the module entirely

1. Set `MAGIC_LINK_ENABLED = false` and `TOTP_ENABLED = false`.
2. Skip the SQL migration (or keep the tables empty).
3. PHPMailer is only required for magic-link emails.
4. The framework continues to work for traditional session-based login.

The `Jwt` and `Totp` classes never run unless an API endpoint is hit.

---

## Cron / maintenance

Add a daily task (cPanel cron):

```
0 3 * * * /usr/bin/php /home/utente/system/cron/auth_purge.php >/dev/null 2>&1
```

Sample script `system/cron/auth_purge.php`:

```php
<?php
require __DIR__ . '/../bootstrap.php';
cleanup_old_logs();
RefreshTokenModel::purgeExpired();
JwtBlacklistModel::purgeExpired();
MagicLinkModel::purgeExpired();
```
