# TemplateBase — PHP Zero-Trust Micro-Framework (Production-Ready, GDPR)

Template PHP vanilla per applicazioni server-rendered su hosting condiviso (cPanel). Filosofia: **Zero-Trust by default, COBOL-style esplicito** — ogni confine di fiducia è dichiarato nel codice, niente magia nascosta, niente dipendenze runtime.

Audit comparativo di partenza: [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) · Checklist di deploy: [`INSTALL.md`](./INSTALL.md) · Estensione Auth: [`docs/AUTH_MODULE.md`](./docs/AUTH_MODULE.md)

---

## Filosofia: Zero-Trust / COBOL

- **Zero-Trust**: nessuna query, redirect, upload o output è fidato per default. La Row-Level Security (`WHERE id_utente = ?`) è obbligatoria nei model. Gli input vanno validati, gli output escapati con `h()`.
- **COBOL-style**: nessun ORM, nessun DI container, nessun hidden state. Il flusso è leggibile dall'alto verso il basso: `index.php → bootstrap.php → Router → Controller → Model → View`. Ogni file del nucleo si apre con `if (!defined('SECURE_ACCESS')) die;`.

---

## Albero del progetto

```
~/
├── AUDIT_REPORT.md
├── README.md
├── INSTALL.md
├── docs/
│   └── AUTH_MODULE.md
├── database/
│   └── auth_module.sql
├── .gitignore
│
├── system/                          # Nucleo (deny-all)
│   ├── .htaccess
│   ├── bootstrap.php                # Costanti, autoloader, sessione, cleanup log
│   ├── Logger.php                   # Log GDPR + rotazione giornaliera + sottocartelle
│   ├── Database.php                 # MySQLi singleton + prepared + auto-types
│   ├── Security.php                 # h(), CSRF, Validator
│   ├── Router.php                   # Convention-based + /api/*
│   ├── RateLimiter.php              # Throttle filesystem-based
│   ├── Mailer.php                   # PHPMailer wrapper (SMTP)
│   ├── Jwt/
│   │   └── Jwt.php                  # HS256 + JTI + blacklist
│   ├── Security/
│   │   └── Totp.php                 # RFC 6238
│   └── lib/
│       └── PHPMailer/               # vendored (vedi README dentro)
│
├── app/                             # Codice app (deny-all)
│   ├── .htaccess
│   ├── Controllers/
│   │   ├── BaseController.php       # + requireJwt + getJsonInput
│   │   ├── HomeController.php
│   │   ├── DashboardController.php
│   │   └── Api/
│   │       ├── AuthController.php
│   │       ├── MagicLinkController.php
│   │       └── TwoFactorController.php
│   ├── Models/
│   │   ├── UserModel.php            # + TOTP helpers
│   │   ├── RefreshTokenModel.php
│   │   ├── JwtBlacklistModel.php
│   │   └── MagicLinkModel.php
│   └── Views/
│       └── home.php
│
├── config/                          # Credenziali + costanti (deny-all)
│   ├── .htaccess
│   ├── constants.php
│   ├── config.template.php          # committato
│   └── config.php                   # NON committato
│
├── logs/                            # Log categorizzati (deny-all + no-exec)
│   ├── .htaccess
│   ├── security/
│   ├── debug/
│   ├── db/
│   ├── errors/
│   └── ratelimit/
│
└── public/                          # Document Root
    ├── .htaccess                    # Routing + CSP + security headers
    └── index.php                    # Front controller
```

---

## Installazione (cPanel / shared hosting)

1. Carica la struttura nella HOME cPanel (es. `/home/utente/`).
   - Le cartelle `system/`, `app/`, `config/`, `logs/`, `database/`, `docs/` al livello `~/`
   - Il contenuto di `public/` dentro `~/public_html/` **oppure** punta il Document Root a `~/public`.
2. `cp config/config.template.php config/config.php` e compila DB, JWT secret, SMTP.
3. `chmod 600 config/config.php`
4. `chmod 770 logs` (il web server deve poter scrivere)
5. Crea le tabelle: lo SQL base + `database/auth_module.sql`. Vedi [`INSTALL.md`](./INSTALL.md).
6. (Solo se serve email/magic-link) scarica PHPMailer in `system/lib/PHPMailer/src/` — istruzioni in `system/lib/PHPMailer/README.md`.
7. Cambia `APP_ENV = 'production'` in `config/constants.php`.

---

## Configurazione

### `config/config.php` (credenziali)
Array PHP con sezioni `db`, `app_secret`, `app.base_url`, `jwt`, `magic_link`, `mail`. Non committare mai. Permessi consigliati: `600`.

### `config/constants.php` (costanti di policy)

| Costante | Scopo |
| --- | --- |
| `APP_ENV` | `development` o `production`. |
| `MAX_LOGIN_ATTEMPTS` / `LOGIN_TIMEOUT_MINUTES` | Lockout login. |
| `SESSION_LIFETIME` / `SESSION_REGENERATE_ID` | Session policy. |
| `PASSWORD_ALGO` / `PASSWORD_COST` | Argon2id default. |
| `LOG_ROTATION_DAYS` | Pulizia log oltre N giorni. |
| `LOG_IP_MASK` / `LOG_EMAIL_HASH_ALGO` | GDPR pseudonymization. |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | Throttle base. |
| `CSRF_TOKEN_LENGTH` / `CSRF_EXPIRY` | CSRF policy. |
| `JWT_ACCESS_EXPIRY` / `JWT_REFRESH_EXPIRY` | TTL token. |
| `MAGIC_LINK_ENABLED` / `MAGIC_LINK_EXPIRY` | Passwordless. |
| `TOTP_ENABLED` / `TOTP_DIGITS` / `TOTP_PERIOD` | 2FA. |

---

## Logging GDPR-Compliant

Struttura: `/logs/{security,debug,db,errors,ratelimit}/{categoria}-YYYY-MM-DD.log`. Rotazione **giornaliera** + cleanup automatico (1% probabilità) basato su `LOG_ROTATION_DAYS`.

Pseudonymization automatica di `email`, `ip`, `user_ip`, `client_ip`, `remote_addr`. Eccezione `gdpr_sensitive=1` valida solo per categoria `security`.

---

## Rate Limiting

Vedi `system/RateLimiter.php` — filesystem-based, atomic write con `LOCK_EX`.

```php
$rl = new RateLimiter('login:' . $ip);
if (!$rl->throttle()) { http_response_code(429); die('Too many requests'); }
```

---

## Sicurezza

### CSRF, CSP, RLS, Sessione, Auth password
(invariati rispetto al template base — vedi sezioni dedicate sopra)

### Auth Module (estensione modulare)

| Mechanism | Stato | Endpoint principali |
|-----------|-------|---------------------|
| JWT (HS256) | sempre attivo se le rotte `/api/*` sono usate | `/api/auth/{login,refresh,logout,me}` |
| Magic Link | toggle `MAGIC_LINK_ENABLED` | `/api/magic/{request,verify}` |
| TOTP 2FA | toggle `TOTP_ENABLED` | `/api/2fa/{setup,enable,disable,status}` |

Caratteristiche:
- Rotazione refresh-token con revoca a catena in caso di reuse.
- Blacklist JTI in DB (purga via cron).
- Magic-link: token in chiaro inviato per email, **solo** sha256 in DB, single-use atomico.
- TOTP RFC 6238 (Google Authenticator), secret base32 in DB.
- Rate limit per IP su login/magic.
- Logging GDPR su tutte le failure.

Documentazione completa: [`docs/AUTH_MODULE.md`](./docs/AUTH_MODULE.md). Schema DB: [`database/auth_module.sql`](./database/auth_module.sql).

---

## Come estendere

### Endpoint HTML
```php
// app/Controllers/ReportController.php
final class ReportController extends BaseController {
    public function index(): void {
        $userId = $this->requireAuth();
        $this->view('report', ['rows' => MyModel::listForUser($userId)]);
    }
}
```

### Endpoint API JWT-protetto
```php
// app/Controllers/Api/UsersController.php (route: /api/users/me)
final class UsersController extends BaseController {
    public function me(): void {
        $payload = $this->requireJwt();
        $user = UserModel::findByIdInternal((int)$payload['user_id']);
        $this->json(['user' => $user]);
    }
}
```
Aggiungi `'users' => 'UsersController'` nella resourceMap di `Router::dispatchApi`.

---

## Riferimenti rapidi

- **Escape HTML**: `<?= h($value) ?>`
- **Form POST**: `<?= CSRF::field() ?>` + `$this->requireCsrf()`
- **Query**: `Database::fetchOne/fetchAll/insert/execute`
- **Log**: `Logger::security|debug|db|error($msg, $context)`
- **JWT**: `Jwt::encode($payload, JWT_ACCESS_EXPIRY)` / `Jwt::decode($token)`
- **TOTP**: `Totp::generateSecret()` / `Totp::verify($secret, $code)`
- **Email**: `Mailer::send($to, $subject, $body)`

---

## Checklist Production

1. `APP_ENV = 'production'` in `constants.php`
2. `config/config.php` con permessi `600` + JWT secret 32+ byte
3. `chmod 770 logs` e sottocartelle
4. Document Root → `public/`
5. HTTPS obbligatorio
6. CSP hardening: rimuovere `'unsafe-inline'`, passare a nonce
7. `TRUSTED_PROXIES` se dietro proxy
8. Cron giornaliero: `RefreshTokenModel::purgeExpired()`, `JwtBlacklistModel::purgeExpired()`, `MagicLinkModel::purgeExpired()`
9. PHPMailer presente in `system/lib/PHPMailer/src/` (solo se magic-link attivo)
