# Auth Module

Modular authentication extension for the TemplateBase framework.
Provides three independent, deactivable mechanisms:

- **JWT (HS256)** — stateless API access tokens con refresh-rotation atomica, JTI blacklist DB-backed, e `token_version` per revoca istantanea multi-device
- **Magic Link** — passwordless login via email (single-use, hashed in DB, gated da TOTP se l'utente ha 2FA attivo)
- **TOTP 2FA** — RFC 6238 (Google Authenticator compatible)

Tutti i flussi riutilizzano le primitive del framework: `SECURE_ACCESS` guard,
`Logger` (GDPR pseudonymisation con pepper HMAC), `RateLimiter` (static),
prepared statements, Zero-Trust, `Env::isDev()`, `Config::get/require`.

---

## Configuration

### Constants — `config/constants.php`

```php
define('APP_ENV', 'production');           // default sicuro
define('JWT_ALGO', 'HS256');
define('JWT_ACCESS_EXPIRY', 900);          // 15 minutes
define('JWT_REFRESH_EXPIRY', 604800);      // 7 days
define('JWT_ISSUER', APP_NAME);
define('JWT_BLACKLIST_DRIVER', 'database'); // only 'database' supported
define('MAGIC_LINK_ENABLED', true);
define('MAGIC_LINK_EXPIRY', 600);          // 10 minutes
define('TOTP_ENABLED', true);
define('API_INPUT_MAX_BYTES', 65536);      // hard cap body JSON
define('RATE_LIMIT_MAX_AGE_DAYS', 7);
```

Disable a feature settando il flag `*_ENABLED = false`. Endpoint risponde `404 feature_disabled`.

### Secrets — `config/config.php`

```php
'auth' => [
    'pepper' => '...',  // bin2hex(random_bytes(32)) - HMAC per email/IP/ratelimit
],
'jwt' => [
    'secret_key' => '...',  // 32+ random chars
],
'app' => [
    'base_url' => 'https://example.com',
],
'mail' => [
    'from' => ['address' => '...', 'name' => 'App'],
    'smtp' => [ 'host' => '...', 'port' => 587, 'username' => '...', 'password' => '...', 'encryption' => 'tls' ],
],
```

`Config::require('jwt.secret_key')` aborta con `RuntimeException` se la chiave
manca o e' < 32 char, **anche in production**.

---

## Database migrations

Applicare in ordine:

| File | Contenuto |
|------|-----------|
| `database/auth_module.sql`    | tabelle `refresh_tokens`, `jwt_blacklist`, `magic_links` + colonne `users.totp_*` |
| `database/auth_module_v2.sql` | colonna `users.token_version` per multi-device revocation |

Senza v2, `BaseController::requireJwt` rifiuta TUTTE le richieste Bearer (il
claim `tv` non puo' essere validato vs DB).

---

## Runtime helpers

| Helper | File | Purpose |
|--------|------|---------|
| `Env::isDev()` / `isProd()` | `system/Env.php` | check ambiente centralizzato |
| `Config::get('jwt.secret_key', $default)` | `system/Config.php` | read-only dotted access |
| `Config::require('jwt.secret_key')` | same | throws se mancante, anche in prod |
| `Logger::throwableContext($e)` | `system/Logger.php` | array `[exception,file,line]` per log |
| `Logger::throwableDevBody($e)` | same | array completo `[+ message, trace[]]` per body API in dev |
| `RateLimiter::throttle($key, $max, $window)` | `system/RateLimiter.php` | **static**; ritorna false su throttle |
| `RateLimiter::reset($key)` | same | azzera il counter dopo successo |
| `BaseController::requireMethod('POST')` | base controller | 405 JSON se non match |
| `BaseController::throttleByIp(bucket,$max,$window,$msg)` | base controller | HMAC pepper sulla bucket key |
| `BaseController::issueTokenPair($uid,$email)` | base controller | issue access+refresh con claim `tv` |
| `BaseController::requireJwt()` | base controller | enforce `typ=='access'` + `tv` match |
| `BaseController::getJsonInput()` | base controller | hard cap `API_INPUT_MAX_BYTES`, 413 oltre |

---

## API Endpoints

Tutti gli endpoint accettano e ritornano JSON. Gli errori seguono la forma
`{"error": "<code>"}` con HTTP status appropriato.

In `APP_ENV='development'` le risposte di errore originate da un'eccezione
includono anche `exception`, `message`, `file`, `line`, `trace`.

### JWT

| Method | Path                | Auth   | Body / Notes |
|--------|---------------------|--------|--------------|
| POST   | `/api/auth/login`   | none   | `{email, password, totp?}` — 10 req / 5 min / IP |
| POST   | `/api/auth/refresh` | none   | `{refresh_token}` — rotation atomica; reuse bumpa `token_version` e revoca tutti i token |
| POST   | `/api/auth/logout`  | Bearer | blacklist JTI corrente + bump `token_version` + revoke all refresh |
| GET    | `/api/auth/me`      | Bearer | `{user: {id, email, totp_enabled}}` |

Login/refresh success response:

```json
{
  "access_token":  "eyJ...",
  "refresh_token": "eyJ...",
  "token_type":    "Bearer",
  "expires_in":    900
}
```

Access token claims: `iss, iat, nbf, exp, jti, user_id, email, typ='access', tv`.
Refresh token claims: `iss, iat, nbf, exp, jti, user_id, typ='refresh'`.

### Magic Link

| Method   | Path                | Notes |
|----------|---------------------|-------|
| POST     | `/api/magic/request`| `{email}` — 5 req / 10 min / IP. Risposta uniforme (no enumeration) |
| POST/GET | `/api/magic/verify` | `{token, totp?}` o `?token=...`. Rate-limit 10 / 15 min / IP. Token = 64 hex chars. **Se l'utente ha TOTP attivo serve il code in POST.** |

### 2FA TOTP

| Method | Path              | Auth   | Body     |
|--------|-------------------|--------|----------|
| POST   | `/api/2fa/setup`  | Bearer | —        |
| POST   | `/api/2fa/enable` | Bearer | `{code}` |
| POST   | `/api/2fa/disable`| Bearer | `{code}` |
| GET    | `/api/2fa/status` | Bearer | —        |

---

## Security model

- **Access token**: TTL breve (15 min), HS256, claim obbligatori `iss/iat/exp/nbf/jti`,
  + claim `typ='access'` + `tv` (token_version). `Jwt::decode` rigetta token senza
  i claim obbligatori (defense-in-depth contro forgery via leak della secret key:
  un attaccante non puo' forgiare un token "perpetuo" perche' `exp` e' richiesto e
  il `jti` e' soggetto a blacklist).
- **Refresh token**: TTL lungo (7 days), `typ='refresh'`, JTI persistito in
  `refresh_tokens`. **Rotation atomica** via singolo UPDATE conditional con
  affected_rows check: nessuna finestra TOCTOU permette double-spend.
- **Reuse detection**: se `RefreshTokenModel::rotate` ritorna false (vecchio JTI
  gia' revocato o scaduto), il controller bumpa `token_version` e revoca tutti
  i refresh dell'utente — invalidando istantaneamente sia gli access vivi che
  i refresh vivi multi-device.
- **Multi-device revocation**: `users.token_version` viene confrontato dal
  `requireJwt` con il claim `tv` dell'access token. Logout / cambio password /
  reuse-detection bumpano la colonna → tutti gli access token vivi falliscono
  al successivo `requireJwt`. Costo: +1 SELECT per chiamata protetta.
- **Blacklist**: revoked access JTIs in `jwt_blacklist`.
  `JwtBlacklistModel::isBlacklisted()` e' **fail-closed** in production: un
  outage DB ritorna `true`, quindi un token revocato non passa mai.
- **Magic link**: 32 random bytes (64 hex), sha256-hashed in DB, single-use
  atomico via `UPDATE ... WHERE used_at IS NULL`. IP storato come
  HMAC-SHA256(ip, auth.pepper). **Gated da TOTP**: se l'utente ha 2FA attivo,
  verify richiede anche il code TOTP nel body POST (la GET diretta da email
  ritorna `totp_required`).
- **TOTP**: RFC 6238, Google Authenticator compatibile. Finestra ±1 step (~90s).
  Secret in DB, mai loggato.
- **Rate limiting**: bucket key = `HMAC(ip, auth.pepper)`. Limiti:
  - `/api/auth/login`     : 10 / 5 min / IP
  - `/api/magic/request`  : 5 / 10 min / IP
  - `/api/magic/verify`   : 10 / 15 min / IP
- **Body cap**: `API_INPUT_MAX_BYTES = 65536` (64KB). Oltre, 413 prima del json_decode.
- **Timing oracle**: `UserModel::verifyCredentials` su utente inesistente esegue
  `password_verify` contro un hash dummy generato con lo STESSO algoritmo
  (Argon2id @ PASSWORD_COST). Cached per process: tutte le miss successive
  al primo workerstart riutilizzano l'hash.
- **Logging**: `Logger::sanitizeContext` hash-HMAC dell'email se
  `auth.pepper` presente, altrimenti sha256 backward-compatible. IP
  mascherato (ultimo ottetto = xxx) salvo flag `gdpr_sensitive=1` per eventi
  security (richiesto da DPIA per forensic).

---

## Error handling & debug

Policy **loud-debug / fail-closed**:

| Layer | Success | Failure in `development` | Failure in `production` |
|-------|---------|--------------------------|-------------------------|
| `Mailer::send`           | `true` + `Logger::debug` | exception re-thrown | `false` + `Logger::error` |
| `JwtBlacklistModel::isBlacklisted` | bool | re-thrown | returns `true` (fail-closed) |
| `JwtBlacklistModel::add/purge` | — | re-thrown | logged, returns silently |
| `UserModel::*` (DB ops) | normal | re-thrown via `dbCatch` | logged, safe default |
| `RefreshTokenModel::rotate` | bool | re-thrown su DB error | logged; rotate ritorna false |
| `Jwt::secret()` | secret | — | **throws** anche in prod (fail-fast) |
| `Jwt::decode()` strict | payload | — | ritorna null su claim mancanti |
| `public/index.php` global catch | — | JSON/HTML con file/line/trace | generic 500 |

Body dev su API 5xx:

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

1. `MAGIC_LINK_ENABLED = false`, `TOTP_ENABLED = false`.
2. Skip della migration `auth_module*.sql`.
3. PHPMailer richiesto solo per magic-link.
4. Il framework continua con session-based login.

`Jwt` e `Totp` non girano se non viene hitato un API endpoint.

---

## Cron / maintenance

Script fornito: `system/cron/auth_purge.php` (CLI-only).

Crontab:

```
*/15 * * * * /usr/bin/php /home/utente/system/cron/auth_purge.php >/dev/null 2>&1
```

Purga: `jwt_blacklist` scaduti, `magic_links` scaduti/usati, `refresh_tokens`
scaduti, file `.json` stale in `logs/ratelimit/`.

---

## Known limitations / non-goals

- **No async mail queue**: `MagicLinkController::request` invia mail sincrono.
  Differenza di timing tra `if($user)` (slow SMTP) e `else` (fast log) **e' un
  oracolo user-enumeration**. Mitigazione futura: outbox table + cron sender.
- **Magic-link via GET**: il link nell'email punta a `GET /api/magic/verify?token=...`.
  Email client / proxy / browser history possono leakare il token. Mitigazioni
  presenti: rate-limit, single-use, TTL 10 min, length+charset enforcement,
  TOTP gate. Mitigazione futura: landing page POST + frontend.
- **Token-version costo DB**: ogni `requireJwt` fa 1 SELECT su
  `users.token_version`. E' il prezzo della revoca multi-device su JWT.
- **No `disabled_at` column su users**: account disabilitati non rigettano
  i token vivi. Workaround: chiamare `UserModel::bumpTokenVersion($uid)` quando
  l'account viene disabilitato.
- **Session fingerprint binds `REMOTE_ADDR`+UA**: utenti mobili su rete cellulare
  che cambia IP perdono la sessione web. Non riguarda gli endpoint API (stateless).
