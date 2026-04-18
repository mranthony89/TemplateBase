# INSTALL — Deploy su cPanel / Shared Hosting

Checklist passo-passo. Completa in ordine; salta una voce solo se non applicabile al tuo hosting.

---

## 1. Upload dei file

- [ ] Carica `system/`, `app/`, `config/`, `logs/` nella HOME utente cPanel (es. `/home/utente/`).
- [ ] Carica il contenuto di `public/` nella cartella Document Root (vedi punto 3).
- [ ] Carica `AUDIT_REPORT.md`, `README.md`, `INSTALL.md` al livello HOME (facoltativo ma consigliato per documentazione on-site).

Struttura attesa sul server:

```
/home/utente/
  ├── system/
  ├── app/
  ├── config/
  ├── logs/
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
  - eventuale `mail.from_address`
- [ ] Permessi restrittivi:
      ```
      chmod 600 config/config.php
      ```

---

## 3. Document Root su `public/`

Due strade a seconda del pannello:

**Opzione A — cPanel: Domains → Edit Document Root**
- [ ] Imposta Document Root del dominio su `/home/utente/public`.

**Opzione B — hosting che forza `public_html/`**
- [ ] Sposta il contenuto di `public/` in `public_html/`:
      ```
      mv public/* public_html/
      mv public/.htaccess public_html/
      ```
- [ ] Aggiorna in `system/bootstrap.php` la costante:
      ```
      define('PUBLIC_PATH', ROOT_PATH . '/public_html');
      ```

---

## 4. Permessi cartelle

- [ ] `chmod 750 system app config`
- [ ] `chmod 770 logs` (il web server deve poter scrivere)
- [ ] `chmod 750 logs/security logs/debug logs/db logs/errors`
- [ ] Verifica l'owner: `chown -R utente:utente system app config logs`

---

## 5. Database

- [ ] Crea il database da cPanel → MySQL Databases (es. `utente_tbase`).
- [ ] Crea lo schema minimo:
      ```sql
      CREATE TABLE users (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      ```

---

## 6. Test connessione DB

- [ ] Apri temporaneamente un file di smoke test (poi cancellalo):
      ```php
      <?php
      require_once dirname(__DIR__) . '/system/bootstrap.php';
      $row = Database::fetchOne('SELECT NOW() AS now');
      echo 'DB OK: ' . $row['now'];
      ```
- [ ] Visita l'URL del file e verifica che stampi il timestamp.
- [ ] **Cancella il file di test.**

---

## 7. Ambiente production

- [ ] Imposta in `config/constants.php`:
      ```
      define('APP_ENV', 'production');
      ```
- [ ] Verifica che le pagine di errore non mostrino stack trace.

---

## 8. HTTPS e HSTS

- [ ] Attiva il certificato SSL (Let's Encrypt in cPanel).
- [ ] Forza il redirect HTTP → HTTPS (cPanel: Force HTTPS toggle).
- [ ] Conferma che l'header `Strict-Transport-Security` sia presente (già configurato in `public/.htaccess`).

---

## 9. CSP & hardening (opzionale ma consigliato)

- [ ] Rivedi la CSP in `public/.htaccess`: rimuovi `'unsafe-inline'` dove possibile, passa a nonce per `<script>`.
- [ ] Aggiungi `integrity=` (SRI) ai tag `<script>` verso CDN.

---

## 10. Cron facoltativo

La pulizia log avviene con probabilità 1% per richiesta. Per garantirla:
- [ ] Cron giornaliero:
      ```
      0 3 * * * /usr/bin/php /home/utente/system/bootstrap.php >/dev/null 2>&1
      ```
  (richiede piccolo adattamento: wrappare `cleanup_old_logs()` in uno script CLI dedicato).

---

## Verifica finale

- [ ] `https://tuodominio.it/` risponde con la home del template.
- [ ] `https://tuodominio.it/system/bootstrap.php` → **403** (o 404).
- [ ] `https://tuodominio.it/config/config.php` → **403** (o 404).
- [ ] Gli header di sicurezza sono presenti (check con `curl -I https://tuodominio.it/`).
