# Template Base — PHP Vanilla Micro-Framework (cPanel / Shared Hosting)

Template di partenza per applicazioni PHP server-rendered su hosting condiviso, con focus sulla sicurezza per difetto.

Sintesi dell'audit comparativo fra OraSicurezza e HRM-2 in [`AUDIT_REPORT.md`](./AUDIT_REPORT.md).

---

## Albero delle Directory

```
~/                                    # HOME utente cPanel (NON accessibile via HTTP)
├── AUDIT_REPORT.md                   # Audit comparativo + motivazioni delle scelte
├── README.md                         # Questo file
├── .gitignore                        # Esclude /config/config.php e i log runtime
│
├── system/                           # NUCLEO FRAMEWORK — deny-all
│   ├── .htaccess                     # Require all denied
│   ├── bootstrap.php                 # Costanti, autoloader, error handler, sessione
│   ├── Logger.php                    # Log categorizzati + rotazione giornaliera
│   ├── Database.php                  # MySQLi singleton + prepared + auto-types
│   ├── Security.php                  # h(), CSRF, Validator
│   └── Router.php                    # Convention-based routing
│
├── app/                              # CODICE APPLICATIVO — deny-all
│   ├── .htaccess                     # Require all denied
│   ├── Controllers/
│   │   ├── BaseController.php        # view(), redirect(), json(), requireAuth(), requireCsrf()
│   │   ├── HomeController.php        # Esempio pagina pubblica
│   │   └── DashboardController.php   # Esempio pagina protetta + Row-Level Security
│   ├── Models/
│   │   └── UserModel.php             # Query con ownership check obbligatorio
│   └── Views/
│       └── home.php                  # Template con h() + CSRF::field()
│
├── config/                           # CREDENZIALI + COSTANTI — deny-all
│   ├── .htaccess                     # Require all denied
│   ├── constants.php                 # APP_ENV, MAX_LOGIN_ATTEMPTS, quote, ecc.
│   ├── config.template.php           # Template credenziali DB (committato)
│   └── config.php                    # (NON committato — creare via cp dal template)
│
├── logs/                             # LOG CATEGORIZZATI — deny-all + no-exec
│   ├── .htaccess                     # Require all denied
│   ├── security/                     # CSRF fail, session hijacking, login fail
│   │   └── .htaccess                 # Deny + ForceType text/plain + RemoveHandler PHP
│   ├── debug/                        # Debug applicativo (solo se APP_ENV=development)
│   ├── db/                           # Query lente, errori DB
│   └── errors/                       # PHP errors/exceptions/fatal
│
└── public_html/                      # DOCUMENT ROOT (UNICA cartella accessibile HTTP)
    ├── .htaccess                     # Routing + security headers + blocchi exploit
    └── index.php                     # Front controller (l'unico file PHP web-accessibile)
```

---

## Deploy su cPanel

1. **Upload**: carica tutta la struttura nella tua HOME cPanel (es. `/home/utente/`).
   - `system/`, `app/`, `config/`, `logs/` al livello `~/`
   - Il contenuto di `public_html/` dentro `~/public_html/`

2. **Config DB**:
   ```bash
   cp config/config.template.php config/config.php
   chmod 600 config/config.php
   # poi edita config.php con le credenziali reali
   ```

3. **Permessi**:
   ```bash
   chmod 750 system app config
   chmod 770 logs                     # il web server deve poter scrivere
   chmod 750 logs/security logs/debug logs/db logs/errors
   ```

4. **Database**: crea lo schema minimo (tabella `users`):
   ```sql
   CREATE TABLE users (
     id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
     email VARCHAR(255) UNIQUE NOT NULL,
     password_hash VARCHAR(255) NOT NULL,
     created_at DATETIME DEFAULT CURRENT_TIMESTAMP
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
   ```

5. **Ambiente**: in `config/constants.php` imposta `APP_ENV = 'production'`.

---

## Regole di sviluppo

- Ogni file `/system/` e `/app/` inizia con `if (!defined('SECURE_ACCESS')) die;`
- Output in view: SEMPRE `h($variabile)` — mai `echo $variabile` diretto
- Form POST: SEMPRE `CSRF::field()` nel form + `$this->requireCsrf()` nel controller
- Query DB: SOLO tramite `Database::fetchAll/fetchOne/insert/execute` — niente SQL concatenato
- Query su dati utente: `WHERE id_utente = ?` OBBLIGATORIO (Row-Level Security)
- Password: `password_hash()` e `password_verify()` — mai `md5`/`sha1`/`crypt()` diretto

---

## Controllo rapido

Richiesta a `/` → `public_html/index.php` → `bootstrap.php` → `Router::dispatch()` → `HomeController::index()` → rende `app/Views/home.php` con escape via `h()`.

Qualsiasi richiesta diretta a `/system/bootstrap.php` o `/config/config.php` riceve **403** grazie agli `.htaccess` deny-all. Difesa in profondità: anche senza `.htaccess`, i file non sono raggiungibili perché fuori dal document root.
