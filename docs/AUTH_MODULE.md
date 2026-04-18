# Auth Module

Modular authentication extension for the TemplateBaseSicurezza framework.
Provides three independent, deactivable mechanisms:

- **JWT (HS256)** — stateless API access tokens with refresh-rotation and blacklist
- **Magic Link** — passwordless login via email (single-use, hashed in DB)
- **TOTP 2FA** — RFC 6238 (Google Authenticator compatible)

All flows reuse the framework primitives: `SECURE_ACCESS` guard, `Logger` (GDPR
pseudonymisation), `RateLimiter`, prepared statements, Zero-Trust queries.

---

## Configuration

### Constants — `config/constants.php`

```php
define('JWT_ALGO', 'HS256');
define('JWT_ACCESS_EXPIRY', 900);          // 15 minutes
define('JWT_REFRESH_EXPIRY', 604800);      // 7 days
define('JWT_ISSUER', APP_NAME);
define('JWT_BLACKLIST_DRIVER', 'database');

define('MAGIC_LINK_ENABLED', true);
define('MAGIC_LINK_EXPIRY', 600);          // 10 minutes

define('TOTP_ENABLED', true);
define('TOTP_ISSUER', APP_NAME);
define('TOTP_DIGITS', 6);
define('TOTP_PERIOD', 30);
define('TOTP_ALGO', 'sha1');
```

To deactivate a feature set the `*_ENABLED` flag to `false`. Endpoints will
return `404 feature_disabled`.

### Secrets — `config/config.php`

```php
'jwt' => [
    'secret_key' => '...',  // 32+ random chars (e.g. bin2hex(random_bytes(32)))
],
'magic_link' => [
    'secret_key' => '...',  // reserved for future HMAC use
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
        'encryption' => 'tls',
    ],
],
```

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

### JWT

| Method | Path                | Auth   | Body / Notes |
|--------|---------------------|--------|--------------|
| POST   | `/api/auth/login`   | none   | `{email, password, totp?}` — rate-limited 10/5min/IP |
| POST   | `/api/auth/refresh` | none   | `{refresh_token}` — rotates JTI; reuse revokes ALL user tokens |
| POST   | `/api/auth/logout`  | Bearer | blacklists current JTI + revokes user refresh tokens |
| GET    | `/api/auth/me`      | Bearer | returns `{user: {id, email, totp_enabled}}` |

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

| Method | Path                | Body              |
|--------|---------------------|-------------------|
| POST   | `/api/magic/request`| `{email}`         |
| POST/GET | `/api/magic/verify`| `{token}` or `?token=...` |

`request` always returns 200 to avoid email enumeration.
`verify` returns the same token pair as `/api/auth/login`.

### 2FA TOTP

| Method | Path              | Auth   | Body            |
|--------|-------------------|--------|-----------------|
| POST   | `/api/2fa/setup`  | Bearer | —               |
| POST   | `/api/2fa/enable` | Bearer | `{code}`        |
| POST   | `/api/2fa/disable`| Bearer | `{code}`        |
| GET    | `/api/2fa/status` | Bearer | —               |

`setup` returns the base32 `secret` and an `otpauth://` `provisioning_uri`
for QR-code generation client-side.

---

## Security model

- **Access token**: short TTL (15 min), HS256 signed, `iss`/`exp`/`nbf`/`jti` claims.
- **Refresh token**: long TTL (7 days), `typ=refresh`, JTI persisted in DB.
  Rotation on every refresh; **reuse of a revoked JTI revokes all user tokens**.
- **Blacklist**: revoked access JTIs stored in `jwt_blacklist`; expired rows
  pruned by `JwtBlacklistModel::purgeExpired()` (call it from a daily cron or
  hook into `cleanup_old_logs`).
- **Magic link**: 32 random bytes, sha256-hashed in DB, single-use enforced
  atomically by `UPDATE ... WHERE used_at IS NULL`. IP is stored only as sha256.
- **TOTP**: RFC 6238, Google Authenticator compatible. Window of ±1 step
  (≈90s) tolerates clock skew. Secret stored in DB; **never** logged.
- **Rate limiting**: `/api/auth/login` 10 req / 5 min / IP;
  `/api/magic/request` 5 req / 10 min / IP.
- **Logging**: all failures via `Logger::security` with `gdpr_sensitive=1`
  so IPs and emails are masked/hashed automatically.

---

## Disabling the module entirely

If you don't need the auth module:

1. Set `MAGIC_LINK_ENABLED = false` and `TOTP_ENABLED = false`.
2. Skip the SQL migration.
3. Remove `system/lib/PHPMailer/` (only required for magic-link emails).
4. The framework continues to work for traditional session-based login.

The `Jwt` and `Totp` classes never run unless an API endpoint is hit.

---

## Cron / maintenance

Add a daily task (cPanel cron):

```
php /path/to/system/cron/auth_purge.php
```

Sample script:

```php
<?php
require __DIR__ . '/../bootstrap.php';
RefreshTokenModel::purgeExpired();
JwtBlacklistModel::purgeExpired();
MagicLinkModel::purgeExpired();
```
