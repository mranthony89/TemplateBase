<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * config/constants.php
 * --------------------------------------------------------------------
 * Costanti applicative immutabili, cablate nel codice.
 * Niente valori qui che possano cambiare tra ambienti: quelli vanno
 * in config.php (credenziali) o derivati da APP_ENV.
 * --------------------------------------------------------------------
 */

// Ambiente: 'development' | 'production' | 'staging'
// In production: display_errors=off, debug log spenti
define('APP_ENV', 'production');

// Nome applicazione (usato nelle pagine di errore, email, log)
define('APP_NAME', 'Template Base');

// Sicurezza
define('MAX_LOGIN_ATTEMPTS', 5);           // Lockout dopo N tentativi falliti
define('LOCKOUT_DURATION_SECONDS', 900);   // 15 minuti
define('SESSION_IDLE_TIMEOUT', 1800);      // 30 minuti di inattività
define('CSRF_TOKEN_LENGTH_BYTES', 32);     // 32 byte = 64 char hex

// Upload
define('MAX_UPLOAD_SIZE_BYTES', 10 * 1024 * 1024);   // 10 MB
define('USER_STORAGE_QUOTA_BYTES', 20 * 1024 * 1024); // 20 MB
define('ALLOWED_MIME_TYPES', [
    'image/jpeg', 'image/png', 'image/webp',
    'application/pdf',
]);

// Proxy fidati (per X-Forwarded-For). Vuoto = nessun proxy.
// Esempio: define('TRUSTED_PROXIES', ['10.0.0.1', '10.0.0.2']);
define('TRUSTED_PROXIES', []);

// Rate limiting (Beyond Minimum rispetto Repo A che ha default=false)
define('RATE_LIMIT_ENABLED', true);
define('RATE_LIMIT_REQUESTS', 60);  // richieste/min per IP
