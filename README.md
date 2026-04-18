# TemplateBase — PHP Zero-Trust Micro-Framework (Production-Ready, GDPR)

Template PHP vanilla per applicazioni server-rendered su hosting condiviso (cPanel). Filosofia: **Zero-Trust by default, COBOL-style esplicito** — ogni confine di fiducia è dichiarato nel codice, niente magia nascosta, niente dipendenze runtime.

Audit comparativo di partenza: [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) · Checklist di deploy: [`INSTALL.md`](./INSTALL.md)

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
├── .gitignore
│
├── system/                          # Nucleo (deny-all)
│   ├── .htaccess
│   ├── bootstrap.php                # Costanti, autoloader, sessione, cleanup log
│   ├── Logger.php                   # Log GDPR + rotazione giornaliera + sottocartelle
│   ├── Database.php                 # MySQLi singleton + prepared + auto-types
│   ├── Security.php                 # h(), CSRF, Validator
│   ├── Router.php                   # Convention-based
│   └── RateLimiter.php              # Throttle filesystem-based
│
├── app/                             # Codice app (deny-all)
│   ├── .htaccess
│   ├── Controllers/
│   │   ├── BaseController.php
│   │   ├── HomeController.php
│   │   └── DashboardController.php
│   ├── Models/
│   │   └── UserModel.php
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
│   │   └── .htaccess                # deny + RemoveHandler PHP + ForceType text/plain
│   ├── debug/
│   ├── db/
│   ├── errors/
│   └── ratelimit/                   # creata automaticamente da RateLimiter
│
└── public/                          # Document Root (unica cartella web-accessible)
    ├── .htaccess                    # Routing + CSP moderna + security headers
    └── index.php                    # Front controller (unico PHP raggiungibile via HTTP)
```

---

## Installazione (cPanel / shared hosting)

1. Carica la struttura nella HOME cPanel (es. `/home/utente/`).
   - Le cartelle `system/`, `app/`, `config/`, `logs/` al livello `~/`
   - Il contenuto di `public/` dentro `~/public_html/` **oppure** punta il Document Root a `~/public`.
2. `cp config/config.template.php config/config.php` e compila le credenziali DB.
3. `chmod 600 config/config.php`
4. `chmod 770 logs` (il web server deve poter scrivere)
5. Crea la tabella `users` (vedi [`INSTALL.md`](./INSTALL.md) per lo SQL completo).
6. Cambia `APP_ENV = 'production'` in `config/constants.php`.

---

## Configurazione

### `config/config.php` (credenziali)
Array PHP con sezioni `db`, `app_secret`, `mail`. Non committare mai. Permessi consigliati: `600`.

### `config/constants.php` (costanti di policy)
Definisce i comportamenti del framework:

| Costante | Scopo |
| --- | --- |
| `APP_ENV` | `development` o `production`. Controlla display_errors e log debug. |
| `MAX_LOGIN_ATTEMPTS` / `LOGIN_TIMEOUT_MINUTES` | Lockout progressivo login. |
| `SESSION_LIFETIME` / `SESSION_REGENERATE_ID` | Scadenza sessione e frequenza di rigenerazione ID (anti session-fixation). |
| `PASSWORD_ALGO` / `PASSWORD_COST` | Argon2id di default, fallback BCRYPT per PHP < 7.3. |
| `LOG_ROTATION_DAYS` | Cancellazione automatica log più vecchi di N giorni (default 30). |
| `LOG_IP_MASK` | `true` → maschera l'ultimo ottetto IPv4 nei log. |
| `LOG_EMAIL_HASH_ALGO` | Algoritmo hash per email nei log (default `sha256`). |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | N richieste ammesse nella finestra (secondi). |
| `CSRF_TOKEN_LENGTH` / `CSRF_EXPIRY` | Parametri token CSRF. |
| `TRUSTED_PROXIES` | Whitelist IP proxy per parsing `X-Forwarded-For`. |

---

## Logging GDPR-Compliant

Struttura: `/logs/{security,debug,db,errors,ratelimit}/{categoria}-YYYY-MM-DD.log`.

Rotazione **giornaliera** via nome file. Pulizia **automatica** dei file più vecchi di `LOG_ROTATION_DAYS` invocata con probabilità 1% ad ogni richiesta (`cleanup_old_logs()` in `bootstrap.php`).

### Pseudonimizzazione dati personali

Nei log l'IP e l'email non vengono mai scritti in chiaro:

- **IP**: ultimo ottetto IPv4 mascherato in `xxx` (es. `192.168.1.xxx`). Per IPv6 vengono mascherati gli ultimi 64 bit.
- **Email**: sostituita con `sha256:<hash>` (algoritmo configurabile).

Il mascheramento è automatico: passando al `Logger` un context con chiavi `email`/`ip`/`user_ip`/`client_ip`/`remote_addr`, la sanitizzazione è trasparente.

### Eccezione controllata: `gdpr_sensitive`

Per i log di sicurezza (tentato hijacking, attacco rilevato) può servire l'IP **completo** per indagini forensi. In quel caso il context deve contenere `'gdpr_sensitive' => 1`: in quel log l'IP viene scritto integrale e annotato con `(gdpr_sensitive=1)`. Si applica **solo** ai log di categoria `security`.

Esempio:
```php
Logger::security('Brute force sospetto', [
    'gdpr_sensitive' => 1,
    'ip'             => $_SERVER['REMOTE_ADDR'],
    'email'          => $email, // hashata comunque
]);
```

---

## Rate Limiting

Classe `RateLimiter` filesystem-based in `system/RateLimiter.php`. Counter file in `logs/ratelimit/<sha256(key)>.json`, scrittura atomica con `LOCK_EX`.

```php
if (!RateLimiter::throttle('login:' . $_SERVER['REMOTE_ADDR'])) {
    http_response_code(429);
    die('Troppe richieste');
}
$rem = RateLimiter::remaining('login:...');
RateLimiter::reset('login:...'); // es. dopo login ok
```

Parametri default da `RATE_LIMIT_MAX` (60) e `RATE_LIMIT_WINDOW` (60s), override per-chiamata con secondo/terzo argomento.

---

## Sicurezza

### CSRF
Token per sessione (`random_bytes(CSRF_TOKEN_LENGTH)`), verifica timing-safe via `hash_equals`. Lo prendi nelle view con `CSRF::field()` e lo verifichi nei controller con `$this->requireCsrf()`. Rotazione manuale post-azione sensibile: `CSRF::rotate()`.

### CSP (Content-Security-Policy)
Policy in `public/.htaccess` predisposta per Bootstrap, Chart.js, Google Fonts e same-origin. Include `'unsafe-inline'` per permettere l'ecosistema Bootstrap out-of-the-box.

**Hardening produzione** (commentato nel file `.htaccess`):
1. Sostituire `'unsafe-inline'` su `script-src` con nonce per-request (generare in `bootstrap.php` con `bin2hex(random_bytes(16))` e iniettarlo in `<script nonce="...">`).
2. Sostituire `'unsafe-inline'` su `style-src` con hash SHA-256 dei blocchi residui dopo aver migrato gli `style=""` in classi CSS.
3. Self-hostare le CDN aggiungendo `integrity=` (SRI) ai tag.

### Row-Level Security (RLS)
I metodi di `UserModel` richiedono un `currentUserId` esplicito quando leggono dati personali. Per uso admin esiste il flag `$skipRls = true` ma è loggato (`Logger::security('UserModel::findById RLS blocked')` quando bloccato).

### Session
- Cookie `HttpOnly`, `Secure` (HTTPS), `SameSite=Strict`, prefix `__Host-` su HTTPS.
- Fingerprint binding: `sha256(UA + IP)`. In caso di mismatch → distruggi sessione, log in `security`.
- `session_regenerate_id(true)` ogni `SESSION_REGENERATE_ID` secondi.

### Autenticazione
Password hashate con `PASSWORD_ARGON2ID` (fallback `PASSWORD_BCRYPT`). `UserModel::verifyCredentials` esegue un `password_verify` fake su utente inesistente per prevenire **user enumeration via timing**.

---

## Come estendere

### Aggiungere un endpoint HTML
```php
// app/Controllers/ReportController.php
final class ReportController extends BaseController {
    public function index(): void {
        $userId = $this->requireAuth();
        $data   = MyModel::listForUser($userId);
        $this->view('report', ['rows' => $data]);
    }
}
```
Disponibile su `/report`.

### Aggiungere un endpoint API JSON (same-origin)
```php
// app/Controllers/ApiController.php
final class ApiController extends BaseController {
    public function users(): void {
        $uid = $this->requireAuth();
        $this->requireCsrf();
        if (!RateLimiter::throttle("api:$uid")) {
            $this->json(['error' => 'rate_limited'], 429);
        }
        $this->json(['ok' => true, 'data' => UserModel::findByIdForUser($uid, $uid)]);
    }
}
```

### Login JWT (estensione)
Il template usa sessione PHP. Per JWT aggiungi una classe `system/Jwt.php` (pattern HS256 di HRM-2), un `AuthController::login` che risponde JSON con `access_token` + `refresh_token`, e un middleware `requireJwt()` in `BaseController`. Le credenziali firma vanno in `config/config.php` sotto chiave `jwt.secret` (≥32 byte generati con `random_bytes`).

---

## Riferimenti rapidi

- **Escape HTML**: `<?= h($value) ?>`
- **Form POST**: `<?= CSRF::field() ?>` nel template + `$this->requireCsrf()` nel controller
- **Query**: `Database::fetchOne/fetchAll/insert/execute` — mai SQL concatenato
- **Log**: `Logger::security|debug|db|error($msg, $context)` — sanitizzazione GDPR automatica
- **Redirect**: solo path relativi (il template rifiuta URL esterni)
- **Rate limit**: `RateLimiter::throttle($key)` prima dell'azione costosa

---

## Checklist Production

1. `APP_ENV = 'production'` in `constants.php`
2. `config/config.php` con permessi `600` e credenziali reali
3. `chmod 770 logs` e sottocartelle
4. Document Root puntato a `public/`
5. HTTPS obbligatorio (HSTS preload è già attivo)
6. Rivedere la CSP: eliminare `'unsafe-inline'` e passare a nonce
7. `TRUSTED_PROXIES` valorizzato se l'app è dietro Cloudflare/reverse proxy
