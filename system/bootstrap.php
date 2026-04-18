<?php
/**
 * system/bootstrap.php
 * --------------------------------------------------------------------
 * Punto di ingresso del framework: costanti, autoloader, error handler,
 * avvio sessione sicura. Incluso UNA SOLA VOLTA da public_html/index.php.
 * --------------------------------------------------------------------
 */

// SECURE_ACCESS: chiave comune a tutti i file del nucleo. Se un file
// del template viene richiamato direttamente (es. via URL malevolo),
// muore subito. Definita PRIMA di qualsiasi altra cosa.
define('SECURE_ACCESS', true);

// ROOT_PATH = directory parent di /system/ (es. /home/utente/ su cPanel)
// Usiamo dirname(__DIR__) perché è assoluto e immune a manipolazioni CWD.
define('ROOT_PATH', dirname(__DIR__));

// Path derivati — tutti assoluti
define('SYSTEM_PATH', ROOT_PATH . '/system');
define('APP_PATH',    ROOT_PATH . '/app');
define('CONFIG_PATH', ROOT_PATH . '/config');
define('LOGS_PATH',   ROOT_PATH . '/logs');
define('PUBLIC_PATH', ROOT_PATH . '/public_html');

// Carica costanti applicative e config DB
require_once CONFIG_PATH . '/constants.php';

if (!file_exists(CONFIG_PATH . '/config.php')) {
    http_response_code(500);
    die('Configurazione mancante. Rinomina config.template.php in config.php.');
}
$GLOBALS['config'] = require CONFIG_PATH . '/config.php';

// --------------------------------------------------------------------
// ERROR REPORTING
// In produzione: NIENTE display_errors (i messaggi finirebbero al client
// rivelando path e stack trace). Tutto loggato su /logs/errors/.
// --------------------------------------------------------------------
if (defined('APP_ENV') && APP_ENV === 'development') {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
}

// --------------------------------------------------------------------
// AUTOLOADER PSR-4 minimale per system/ e app/
// --------------------------------------------------------------------
spl_autoload_register(function ($class) {
    // Prova prima /system/, poi /app/Controllers, /app/Models
    $candidates = [
        SYSTEM_PATH . '/' . $class . '.php',
        APP_PATH . '/Controllers/' . $class . '.php',
        APP_PATH . '/Models/' . $class . '.php',
    ];
    foreach ($candidates as $file) {
        if (is_file($file)) {
            require_once $file;
            return;
        }
    }
});

// --------------------------------------------------------------------
// ERROR HANDLER GLOBALI
// Catturano errori/eccezioni/fatal e li scrivono sui log categorizzati.
// Previene leak di stack trace al client.
// --------------------------------------------------------------------
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) return false;
    Logger::error("PHP Error [$severity]: $message in $file:$line");
    // Trasforma in eccezione per gestione uniforme
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

// --------------------------------------------------------------------
// SESSIONE SICURA
// Cookie: HttpOnly (no JS), Secure (solo HTTPS), SameSite=Strict (no CSRF via link).
// Fingerprint: lega la sessione a UA+IP → token rubato da altro dispositivo non funziona.
// --------------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    // Cookie prefix __Host- solo se HTTPS (richiede Secure + Path=/ + no Domain)
    session_name($secure ? '__Host-SID' : 'APPSID');
    session_start();

    // Fingerprint binding (gap 3.8 auto-rilevato in Repo A OraSicurezza)
    $fp = hash('sha256',
        ($_SERVER['HTTP_USER_AGENT'] ?? '') . '|' .
        ($_SERVER['REMOTE_ADDR'] ?? '')
    );
    if (!isset($_SESSION['_fp'])) {
        $_SESSION['_fp'] = $fp;
    } elseif (!hash_equals($_SESSION['_fp'], $fp)) {
        // Possibile hijacking: distruggi sessione e logga
        Logger::security('Session fingerprint mismatch', [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
        session_unset();
        session_destroy();
        http_response_code(401);
        die('Sessione non valida.');
    }

    // Rigenera ID periodicamente (anti session-fixation)
    if (!isset($_SESSION['_born'])) {
        $_SESSION['_born'] = time();
    } elseif (time() - $_SESSION['_born'] > 1800) { // 30 min
        session_regenerate_id(true);
        $_SESSION['_born'] = time();
    }
}
