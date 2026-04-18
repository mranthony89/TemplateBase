# AUDIT COMPARATIVO — OraSicurezza vs HRM-2

**Data:** 2026-04-18
**Obiettivo:** estrarre il meglio dai due repo e definire le scelte per il Template Base.

---

## Tabella Comparativa (Template Base)

**Repo A = OraSicurezza** (web app PHP MVC) · **Repo B = HRM-2** (API JWT + SPA)

| Categoria | Repo A — Debolezza | Repo A — Punto Forza | Repo B — Debolezza | Repo B — Punto Forza | SCELTA FINALE | Motivazione |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Sistema di Logging** | Log su file singoli senza rotazione giornaliera; manca categorizzazione per sottocartelle | Dual-log (DB `security_log` + file), tracking IP/UA/evento completo | `utils/logger.php` non sempre incluso (vedi `cestino.php`, `logs.php`) | Classe `Logger` OOP con livelli strutturati | **Repo A evoluto + classe OOP di B** | Pattern dual-log di A + struttura OOP di B + rotazione giornaliera (`security-YYYY-MM-DD.log`) + sottocartelle `/logs/security/`, `/logs/debug/`, `/logs/db/`, `/logs/errors/` |
| **Protezione Directory** | `app/.htaccess` minimale (31 byte) | `Options -Indexes`, blocco wp-login/xmlrpc/.env/.git, blocco metodi HTTP, path traversal | `FilesMatch` generico; deny non sempre globale | Headers completi in root (HSTS preload, X-Frame, CSP) | **Pattern A + headers B + deny totale + struttura fuori da public_html** | A ha i blocchi pattern migliori, B gli header. Unisco + `Require all denied` + blocco esecuzione PHP in `logs/` |
| **Gestione Sessioni** | Manca fingerprint binding (vuln 3.8 auto-rilevata) | Cookie HttpOnly + SameSite=Strict + Secure | Stateless JWT (no sessione classica) | JWT blacklist + `isRefreshToken` check | **Sessione PHP di A + fingerprint binding (Beyond Minimum)** | Template server-rendered → sessione PHP naturale. Aggiungo `sha256(UA+IP)` anti-hijacking (gap noto) |
| **SQL Injection Prevention** | N/A | 100% PDO prepared statements | `logs.php` struttura discutibile ma usa bind | Classe `Database` statica con helper | **Static helper di B su MySQLi + auto-detect tipi** | Prompt impone MySQLi. Ergonomia di B + auto-detect `i/d/s/b` per rendere impossibile il binding mancante |
| **XSS Prevention** | No funzione `h()` globale | Whitelist tag sicuri, blocco `javascript:`/`data:` nei link, `rel="noopener"` auto | No helper di escape globale | Encryption handler (difesa in profondità, non XSS) | **`h()` globale + whitelist HTML di A** | `h($str) = htmlspecialchars($str, ENT_QUOTES\|ENT_HTML5, 'UTF-8')` + `Security::cleanHtml()` per rich text |
| **CSRF Protection** | N/A | Token 64 char hex (`random_bytes(32)`), `hash_equals()`, 3 fonti, log violazioni | N/A (stateless JWT) | JWT in Bearer → immune per design | **Implementazione Repo A + rotazione post-azione (Beyond Minimum)** | Già al top moderno. Aggiungo rotazione dopo azioni sensibili |
| **File Upload Security** | Filename non sanitizzato (vuln 3.1); race condition quota (3.2) | MIME via `finfo`, storage privato, quota tracking | Encryption handler complesso (fuori scope template) | `file-handler` + `storage-organizer` con categorizzazione | **Pattern A + sanitizzazione filename + update atomico quota** | Fix delle debolezze auto-rilevate. Encryption in roadmap (richiede gestione chiavi) |
| **Validazione Input** | Sparsa nei controller | Validatori inline | `utils/validators.php` centralizzato | Classe `Validator` statica riusabile | **Classe `Validator` di B estesa** | Centralizzato batte inline. Regole: `email`, `int`, `string(min,max)`, `regex`, `in(array)`, `url`, `date` |
| **Gestione Errori/Exception** | N/A | Try/catch nei controller, display errori OFF in prod | `logs.php` struttura try/catch problematica | Error handler nei file corretti | **Handler globale + 404/500 dedicati + log in `/logs/errors/`** | Entrambi mancano di handler globale. Uso `set_error_handler`, `set_exception_handler`, `register_shutdown_function` |

---

## Tabella Comparativa (Modulo Autenticazione Avanzata)

| Categoria | Repo A — Debolezza | Repo A — Punto Forza | Repo B — Debolezza | Repo B — Punto Forza | SCELTA PER L'ESTENSIONE | Motivazione |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Gestione JWT** | Implementazione custom HS256, accoppiata a sessione (uso ibrido) | Verifica `iss`, `aud`, `exp`, `nbf`; `hash_equals` su firma; secret >= 32 byte validato all'avvio | Custom HS256 (`utils/jwt-handler.php`); fragile parsing del Bearer header in più endpoint (`logs.php` usa `str_replace`, `cestino.php` non chiama `isRefreshToken`) | Helper `JwtHandler::decode/encode` riusato in tutti gli endpoint corretti; check `isRefreshToken` per separare access/refresh | **Custom HS256 di B + claim verification di A + JTI univoco** | Niente lib esterne (compat cPanel/PHP 7.4+). Aggiungo `jti` per blacklist, `iss` configurabile, `iat`+`exp` standard, `aud` opzionale per multi-tenant futuro |
| **Refresh Token** | N/A — flusso solo sessione | N/A | Concept presente (campo `is_refresh` nel payload) | Distinzione access/refresh nello stesso schema JWT | **Refresh token come riga DB separata, mai stateless** | Token opaco lungo (random_bytes(64)) salvato hashato in `refresh_tokens`. Rotazione obbligatoria a ogni `/refresh`: il vecchio è revocato. Previene reuse e furto cookie |
| **Blacklist Token** | DB `token_blacklist` controllata su ogni decode | TTL = `exp` originale, cleanup via cron | DB `jwt_blacklist` analogo, ma include `revoked_by` per audit | Campo `revoked_at`, indice su `jti` | **Driver DB di default (`JWT_BLACKLIST_DRIVER=database`) + driver file fallback** | DB scalabile e indicizzabile. File-based per progetti micro o ambienti senza scrittura DB. Auto-pulizia: cancella righe con `exp < NOW()` |
| **Magic Link** | N/A | N/A | N/A | N/A | **Implementazione nuova: token monouso firmato + DB** | Nessuno dei due repo lo implementa. Schema: token = HMAC(payload, magic_link.secret_key); DB `magic_links(id, user_id, token_hash, expires_at, used_at)`. Verifica: `used_at IS NULL` + `expires_at > NOW()`, marca `used_at` atomicamente |
| **2FA / TOTP** | N/A | N/A | N/A | N/A | **Implementazione RFC 6238 (sha1, 30s, 6 digit), compat Google Authenticator** | Niente lib esterne. Secret base32 generato lato server, mostrato 1 sola volta + URL `otpauth://`. Verifica con tolleranza ±1 step (90s window) per drift orologio. Backup codes opzionali in roadmap |
| **Invio Email** | Wrapper `mail()` PHP di base | Funzionante per piccolo volume | `utils/email-handler.php` (8.5KB) ma usa `mail()` nativa | Astrazione semplice riutilizzabile | **PHPMailer (SMTP) obbligatorio** | `mail()` in cPanel finisce in spam. PHPMailer SMTP + STARTTLS è lo standard per email transazionali (login link, OTP). Integrato in `system/lib/PHPMailer/` (download manuale documentato in INSTALL.md) |
| **Rate Limiting su Auth** | Rate limit globale, no lockout login dedicato (vuln 3.7 auto-rilevata) | Tabella `login_attempts` esistente per cron cleanup | Rate limit complesso (`utils/rate-limiter.php` 24KB) ma file-based con cleanup non automatico | Granularità per-endpoint | **`RateLimiter` filesystem del template + chiave per-endpoint+IP+identificatore** | Già implementato nel template base. Per auth: `RateLimiter::throttle("login:$ip", 5, 900)` (5 tentativi / 15 min), `magic-link:$email` (3 / 10 min), `2fa:$user_id` (5 / 5 min) |

---

## Dilemmi Risolti (HALT-AND-ASK)

1. **Gestione credenziali DB** → `config/config.php` (array PHP, no .env). Massima compatibilità cPanel.
2. **Layout cPanel** → `system/app/config/logs` FUORI da `public_html/`. I file non sono accessibili via HTTP per design, non per convenzione `.htaccess`.
3. **Router** → Convention-based (`/home/index` → `HomeController::index()`). Zero config.
4. **JWT lib** → Implementazione custom HS256 (no `firebase/php-jwt` per evitare Composer su shared hosting).
5. **Email** → PHPMailer manualmente vendored in `system/lib/PHPMailer/` (no Composer).
6. **TOTP lib** → Implementazione manuale RFC 6238 (no `pragmarx/google2fa` per evitare Composer).

---

## Beyond Minimum — Migliorie aggiunte rispetto ai due repo

- **Session fingerprint binding** (gap 3.8 auto-rilevato in Repo A)
- **Rotazione giornaliera log** + sottocartelle categorizzate
- **CSRF token rotation** post-azione sensibile
- **Global error/exception handler** con logging dedicato
- **Row-Level Security** forzata nelle query (`WHERE user_id = ?` sempre)
- **Filename sanitization** automatica in upload
- **Quota update atomico** (fix race condition 3.2)
- **Cookie prefix `__Host-`** per session cookie
- **CSP senza `unsafe-inline`** (evita il debito tecnico di Repo A §2.1)
- **GDPR pseudonymization** automatica nei log (mask IP, hash email)
- **JWT JTI univoco** per blacklist precisa (no blacklist per "tutti i token di un utente")
- **Refresh token rotation** obbligatoria a ogni refresh
- **Lockout login** dedicato (fix vuln 3.7 OraSicurezza) via `RateLimiter`
