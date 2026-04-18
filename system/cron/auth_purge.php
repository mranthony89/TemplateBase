<?php
/**
 * system/cron/auth_purge.php
 * --------------------------------------------------------------------
 * Manutenzione periodica del modulo auth.
 *
 * Cosa purga
 *   1. jwt_blacklist  : righe con expires_at < NOW()
 *   2. magic_links    : righe scadute o gia' consumate (used_at IS NOT NULL)
 *   3. refresh_tokens : righe con expires_at < NOW()
 *   4. logs/ratelimit : file .json piu' vecchi di RATE_LIMIT_MAX_AGE_DAYS
 *                      (fallback 7 giorni)
 *
 * Come eseguirlo
 *   CLI (consigliato, crontab):
 *     */15 * * * *  /usr/bin/php /path/to/app/system/cron/auth_purge.php
 *
 *   HTTP (solo se la CLI non e' disponibile):
 *     GET /system/cron/auth_purge.php?token=<CRON_TOKEN>
 *     richiede la costante CRON_TOKEN definita in config/constants.php.
 *     Senza token o da IP pubblico risponde 403.
 *
 * Policy errori (loud-debug / fail-open per manutenzione)
 *   Ogni fase e' isolata in try/catch: un fallimento non blocca le
 *   successive. In development gli errori vengono rilanciati al termine
 *   per visibilita' immediata; in produzione vengono solo loggati.
 *
 * Output
 *   - CLI : righe testuali su stdout + exit code 0 / 1
 *   - HTTP: JSON con esito e contatori
 * --------------------------------------------------------------------
 */

declare(strict_types=1);

$isCli = (PHP_SAPI === 'cli');

require_once dirname(__DIR__) . '/bootstrap.php';

// --------------------------------------------------------------------
// Accesso
// --------------------------------------------------------------------
if (!$isCli) {
    $token = $_GET['token'] ?? '';
    $expected = defined('CRON_TOKEN') ? (string)CRON_TOKEN : '';
    if ($expected === '' || !is_string($token) || !hash_equals($expected, $token)) {
        Logger::security('auth_purge: HTTP access denied', [
            'gdpr_sensitive' => 1,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        ]);
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'forbidden']);
        exit;
    }
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------
$isDev = defined('APP_ENV') && APP_ENV === 'development';
$errors = [];
$report = [
    'started_at'      => date('c'),
    'jwt_blacklist'   => null,
    'magic_links'     => null,
    'refresh_tokens'  => null,
    'ratelimit_files' => null,
];

$run = function (string $label, callable $fn) use (&$errors, &$report) {
    try {
        $report[$label] = $fn();
    } catch (\Throwable $e) {
        Logger::error("auth_purge[$label] failed: " . $e->getMessage(), [
            'file'  => $e->getFile(),
            'line'  => $e->getLine(),
            'trace' => $e->getTraceAsString(),
        ]);
        $errors[] = ['phase' => $label, 'message' => $e->getMessage()];
        $report[$label] = 'error';
    }
};

// --------------------------------------------------------------------
// Fase 1-3: purge DB
// --------------------------------------------------------------------
$run('jwt_blacklist', function () {
    JwtBlacklistModel::purgeExpired();
    return 'ok';
});

$run('magic_links', function () {
    MagicLinkModel::purgeExpired();
    return 'ok';
});

$run('refresh_tokens', function () {
    RefreshTokenModel::purgeExpired();
    return 'ok';
});

// --------------------------------------------------------------------
// Fase 4: pulizia file RateLimiter piu' vecchi di N giorni
// --------------------------------------------------------------------
$run('ratelimit_files', function () {
    $dir = LOGS_PATH . '/ratelimit';
    if (!is_dir($dir)) return 0;

    $days   = defined('RATE_LIMIT_MAX_AGE_DAYS') ? (int)RATE_LIMIT_MAX_AGE_DAYS : 7;
    $cutoff = time() - ($days * 86400);
    $deleted = 0;

    $dh = opendir($dir);
    if ($dh === false) return 0;
    while (($entry = readdir($dh)) !== false) {
        if ($entry === '.' || $entry === '..') continue;
        if (substr($entry, -5) !== '.json') continue;
        $path = $dir . '/' . $entry;
        if (!is_file($path)) continue;
        if (@filemtime($path) < $cutoff && @unlink($path)) {
            $deleted++;
        }
    }
    closedir($dh);
    return $deleted;
});

$report['finished_at'] = date('c');
$report['errors']      = $errors;
$ok = empty($errors);

Logger::info('auth_purge completed', $report);

// --------------------------------------------------------------------
// Output
// --------------------------------------------------------------------
if ($isCli) {
    foreach ($report as $k => $v) {
        if (is_array($v)) $v = json_encode($v);
        echo str_pad($k, 18) . ' : ' . $v . PHP_EOL;
    }
    if ($isDev && !$ok) {
        // loud-debug: in dev rilancia la prima eccezione dopo aver completato
        // tutte le fasi, cosi' nessuna fase resta indietro ma l'errore e'
        // comunque visibile.
        throw new RuntimeException('auth_purge: ' . $errors[0]['message']);
    }
    exit($ok ? 0 : 1);
}

header('Content-Type: application/json; charset=utf-8');
http_response_code($ok ? 200 : 500);
echo json_encode($report, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

if ($isDev && !$ok) {
    throw new RuntimeException('auth_purge: ' . $errors[0]['message']);
}
