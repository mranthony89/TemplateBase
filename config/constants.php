<?php
if (!defined('SECURE_ACCESS')) die;

// Ambiente
define('APP_ENV', 'development'); // 'production' per il deploy
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

// CSRF
define('CSRF_TOKEN_LENGTH', 32);
define('CSRF_EXPIRY', 3600);

// Proxy
define('TRUSTED_PROXIES', []);
