<?php
define('SECURE_ACCESS', true);
define('ROOT_PATH', dirname(__DIR__));
define('SYSTEM_PATH', ROOT_PATH . '/system');
define('APP_PATH',    ROOT_PATH . '/app');
define('CONFIG_PATH', ROOT_PATH . '/config');
define('LOGS_PATH',   ROOT_PATH . '/logs');
define('PUBLIC_PATH', ROOT_PATH . '/public');

require_once CONFIG_PATH . '/constants.php';

if (!file_exists(CONFIG_PATH . '/config.php')) {
    http_response_code(500);
    die('Configurazione mancante. Rinomina config.template.php in config.php.');
}
$GLOBALS['config'] = require CONFIG_PATH . '/config.php';

// Helper Config (usato da Jwt, Mailer, controller). Caricato esplicitamente
// perché l'autoloader potrebbe non essere ancora registrato.
require_once SYSTEM_PATH . '/Config.php';

if (defined('APP_ENV') && APP_ENV === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    ini_set('log_errors', '1');
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    ini_set('log_errors', '1');
}

spl_autoload_register(function ($class) {
    $candidates = [
        SYSTEM_PATH . '/' . $class . '.php',
        SYSTEM_PATH . '/Jwt/' . $class . '.php',
        SYSTEM_PATH . '/Security/' . $class . '.php',
        APP_PATH . '/Controllers/' . $class . '.php',
        APP_PATH . '/Controllers/Api/' . $class . '.php',
        APP_PATH . '/Models/' . $class . '.php',
    ];
    foreach ($candidates as $file) {
        if (is_file($file)) { require_once $file; return; }
    }
});

require_once SYSTEM_PATH . '/RateLimiter.php';

function cleanup_old_logs(): void
{
    if (!defined('LOGS_PATH') || !is_dir(LOGS_PATH)) return;
    $days = defined('LOG_ROTATION_DAYS') ? (int)LOG_ROTATION_DAYS : 30;
    $cutoff = time() - ($days * 86400);
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(LOGS_PATH, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        if (strtolower($f->getExtension()) !== 'log') continue;
        if ($f->getMTime() < $cutoff) @unlink($f->getPathname());
    }
}

if (mt_rand(1, 100) === 1) cleanup_old_logs();

set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) return false;
    Logger::error("PHP Error [$severity]: $message in $file:$line");
    throw new ErrorException($message, 0, $severity, $file, $line);
});

set_exception_handler(function ($e) {
    Logger::error('Uncaught Exception: ' . $e->getMessage()
        . ' in ' . $e->getFile() . ':' . $e->getLine()
        . "\n" . $e->getTraceAsString());
    http_response_code(500);
    if (defined('APP_ENV') && APP_ENV === 'development') {
        echo '<pre>' . htmlspecialchars((string)$e, ENT_QUOTES, 'UTF-8') . '</pre>';
    } else {
        echo 'Errore interno del server.';
    }
});

register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        Logger::error('Fatal: ' . $err['message'] . ' in ' . $err['file'] . ':' . $err['line']);
    }
});

$isApi = isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/api/') !== false;

if (!$isApi && session_status() === PHP_SESSION_NONE) {
    $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $lifetime = defined('SESSION_LIFETIME') ? (int)SESSION_LIFETIME : 0;
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    if ($lifetime > 0) {
        ini_set('session.gc_maxlifetime', (string)$lifetime);
    }
    session_name($secure ? '__Host-SID' : 'APPSID');
    session_start();

    $fp = hash('sha256',
        ($_SERVER['HTTP_USER_AGENT'] ?? '') . '|' .
        ($_SERVER['REMOTE_ADDR'] ?? '')
    );
    if (!isset($_SESSION['_fp'])) {
        $_SESSION['_fp'] = $fp;
    } elseif (!hash_equals($_SESSION['_fp'], $fp)) {
        Logger::security('Session fingerprint mismatch', [
            'gdpr_sensitive' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
        session_unset();
        session_destroy();
        http_response_code(401);
        die('Sessione non valida.');
    }

    $regenInterval = defined('SESSION_REGENERATE_ID') ? (int)SESSION_REGENERATE_ID : 1800;
    if (!isset($_SESSION['_born'])) {
        $_SESSION['_born'] = time();
    } elseif (time() - $_SESSION['_born'] > $regenInterval) {
        session_regenerate_id(true);
        $_SESSION['_born'] = time();
    }
}
