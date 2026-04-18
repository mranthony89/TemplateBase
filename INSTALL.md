# INSTALL — Deploy su cPanel / Shared Hosting

Checklist passo-passo. Completa in ordine; salta una voce solo se non applicabile al tuo hosting.

---

## 1. Upload dei file

- [ ] Carica `system/`, `app/`, `config/`, `logs/`, `database/`, `docs/` nella HOME utente cPanel (es. `/home/utente/`).
- [ ] Carica il contenuto di `public/` nella cartella Document Root (vedi punto 3).
- [ ] Carica `AUDIT_REPORT.md`, `README.md`, `INSTALL.md` al livello HOME (facoltativo).

Struttura attesa sul server:

```
/home/utente/
  ├── system/
  ├── app/
  ├── config/
  ├── logs/
  ├── database/
  ├── docs/
  └── public/         ← oppure punta il Document Root qui (punto 3)
```

---

## 2. Configurazione credenziali

- [ ] Duplica il template:
      ```
      cp config/config.template.php config/config.php
      ```
- [ ] Edita `config/config.php` con:
  - credenziali database (`host`, `name`, `user`, `pass`)
  - `app_secret` — generalo con:
      ```
      php -r "echo bin2hex(random_bytes(32));"
      ```
  - `jwt.secret_key` — stesso comando, **almeno 32 char** (richiesto dalla classe `Jwt`)
  - `magic_link.secret_key` — stesso comando
  - `app.base_url` — URL pubblico (es. `https://example.com`) usato per i link delle email
  - `mail.from.address` / `mail.from.name`
  - `mail.smtp.{host,port,username,password,encryption}` (per magic-link/2FA recovery)
- [ ] Permessi restrittivi:
      ```
      chmod 600 config/config.php
      ```

---

## 3. Document Root su `public/`

**Opzione A — cPanel: Domains → Edit Document Root**
- [ ] Imposta Document Root del dominio su `/home/utente/public`.

**Opzione B — hosting che forza `public_html/`**
- [ ] Sposta il contenuto di `public/` in `public_html/`:
      ```
      mv public/* public_html/
      mv public/.htaccess public_html/
      ```
- [ ] Aggiorna in `system/bootstrap.php`:
      ```
      define('PUBLIC_PATH', ROOT_PATH . '/public_html');
      ```

---

## 4. Permessi cartelle

- [ ] `chmod 750 system app config database docs`
- [ ] `chmod 770 logs` (web server deve scrivere)
- [ ] `chmod 750 logs/security logs/debug logs/db logs/errors`
- [ ] Verifica owner: `chown -R utente:utente system app config logs database docs`

---

## 5. PHPMailer (richiesto solo se Magic Link / email attive)

- [ ] Scarica l'ultima release stabile da <https://github.com/PHPMailer/PHPMailer/releases>.
- [ ] Estrai e copia **solo** il contenuto della cartella `src/` in:
      ```
      system/lib/PHPMailer/src/
      ```
- [ ] Verifica che esistano:
      ```
      system/lib/PHPMailer/src/PHPMailer.php
      system/lib/PHPMailer/src/SMTP.php
      system/lib/PHPMailer/src/Exception.php
      ```
- [ ] In assenza di questi file, `Mailer::send()` lancerà `RuntimeException`.
      Se non hai bisogno delle email, imposta `MAGIC_LINK_ENABLED = false` in `constants.php`.

Vedi anche `system/lib/PHPMailer/README.md`.

---

## 6. Database

- [ ] Crea il database da cPanel → MySQL Databases (es. `utente_tbase`).
- [ ] Crea lo schema base:
      ```sql
      CREATE TABLE users (
        id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email         VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      ```
- [ ] **Auth module** — applica la migration:
      ```
      mysql -u utente_user -p utente_tbase < database/auth_module.sql
      ```
      Aggiunge colonne `totp_secret`, `totp_enabled` a `users` e crea le tabelle
      `refresh_tokens`, `jwt_blacklist`, `magic_links`. Vedi `docs/AUTH_MODULE.md`.

---

## 7. Test connessione DB

- [ ] Smoke test (cancellalo subito dopo):
      ```php
      <?php
      require_once dirname(__DIR__) . '/system/bootstrap.php';
      $row = Database::fetchOne('SELECT NOW() AS now');
      echo 'DB OK: ' . $row['now'];
      ```
- [ ] Visita l'URL e verifica.
- [ ] **Cancella il file di test.**

---

## 8. Ambiente production

- [ ] In `config/constants.php`:
      ```
      define('APP_ENV', 'production');
      ```
- [ ] Verifica che gli errori non mostrino stack trace.

---

## 9. HTTPS e HSTS

- [ ] Attiva SSL (Let's Encrypt in cPanel).
- [ ] Forza redirect HTTP → HTTPS.
- [ ] Conferma `Strict-Transport-Security` nei response header.

---

## 10. CSP & hardening (opzionale ma consigliato)

- [ ] Rivedi la CSP in `public/.htaccess`, rimuovi `'unsafe-inline'`, passa a nonce.
- [ ] Aggiungi `integrity=` (SRI) ai tag `<script>` verso CDN.

---

## 11. Cron — pulizia automatica

La pulizia log gira con probabilità 1% per richiesta. Per garantire purging
costante (log + token scaduti):

- [ ] Crea `system/cron/auth_purge.php`:
      ```php
      <?php
      require __DIR__ . '/../bootstrap.php';
      cleanup_old_logs();
      RefreshTokenModel::purgeExpired();
      JwtBlacklistModel::purgeExpired();
      MagicLinkModel::purgeExpired();
      ```
- [ ] Cron giornaliero:
      ```
      0 3 * * * /usr/bin/php /home/utente/system/cron/auth_purge.php >/dev/null 2>&1
      ```

---

## 12. Verifica finale

- [ ] `https://tuodominio.it/` → home del template.
- [ ] `https://tuodominio.it/system/bootstrap.php` → **403** (o 404).
- [ ] `https://tuodominio.it/config/config.php` → **403** (o 404).
- [ ] `https://tuodominio.it/database/auth_module.sql` → **403** (o 404).
- [ ] `https://tuodominio.it/system/lib/PHPMailer/src/PHPMailer.php` → **403** (o 404).
- [ ] Header sicurezza presenti: `curl -I https://tuodominio.it/`.
- [ ] (Se auth module attivo) test API:
      ```
      curl -X POST https://tuodominio.it/api/auth/login \
        -H 'Content-Type: application/json' \
        -d '{"email":"u@e.it","password":"x"}'
      ```
