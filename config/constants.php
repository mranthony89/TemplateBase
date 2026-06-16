<?php
if (!defined('SECURE_ACCESS')) die;

// Ambiente - default sicuro: production. Cambialo a 'development' SOLO
// in locale o su domini dev/staging. In production il body delle risposte
// 5xx NON include exception/file/line/trace; in development li include
// tutti (loud-debug).
define('APP_ENV', 'production');
define('APP_NAME', 'TemplateBase');

// Sicurezza Login
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_TIMEOUT_MINUTES', 15);
define('SESSION_LIFETIME', 7200);
define('SESSION_REGENERATE_ID', 1800);

// Hashing
define('PASSWORD_ALGO', PASSWORD_ARGON2ID); // o PASSWORD_BCRYPT per PHP < 7.3
define('PASSWORD_COST', 12);

// Logging & GDPR
define('LOG_ROTATION_DAYS', 30);
define('LOG_IP_MASK', true);       // Maschera ultimo ottetto IPv4
define('LOG_EMAIL_HASH_ALGO', 'sha256');

// Rate Limiting
define('RATE_LIMIT_MAX', 60);
define('RATE_LIMIT_WINDOW', 60);
// Eta' massima dei file in logs/ratelimit/ prima della cancellazione da
// parte di system/cron/auth_purge.php.
define('RATE_LIMIT_MAX_AGE_DAYS', 7);

// Hard cap del body JSON in ingresso (POST /api/*). Body piu' grandi
// vengono rifiutati con 413 prima del json_decode.
define('API_INPUT_MAX_BYTES', 65536); // 64KB

// CSRF
define('CSRF_TOKEN_LENGTH', 32);
define('CSRF_EXPIRY', 3600);

// Proxy
define('TRUSTED_PROXIES', []);

// --- Modulo Autenticazione Avanzata ---
// JWT
define('JWT_ALGO', 'HS256');
define('JWT_ACCESS_EXPIRY', 900);       // 15 minuti
define('JWT_REFRESH_EXPIRY', 604800);   // 7 giorni
define('JWT_ISSUER', APP_NAME);
define('JWT_BLACKLIST_DRIVER', 'database'); // solo 'database' supportato

// Magic Link
define('MAGIC_LINK_ENABLED', true);
define('MAGIC_LINK_EXPIRY', 600);       // 10 minuti

// 2FA TOTP
define('TOTP_ENABLED', true);
define('TOTP_ISSUER', APP_NAME);
define('TOTP_DIGITS', 6);
define('TOTP_PERIOD', 30);
define('TOTP_ALGO', 'sha1');
