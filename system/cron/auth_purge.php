<?php
/**
 * system/cron/auth_purge.php
 * --------------------------------------------------------------------
 * Manutenzione periodica del modulo auth.
 *
 * Cosa purga
 *   1. jwt_blacklist  : righe con expires_at < NOW()
 *   2. magic_links    : righe scadute o gia' consumate
 *   3. refresh_tokens : righe con expires_at < NOW()
 *   4. logs/ratelimit : file .json piu' vecchi di RATE_LIMIT_MAX_AGE_DAYS
 *                      (fallback 7 giorni)
 *
 * Esecuzione: SOLO CLI.
 *   Crontab tipico:
 *     */15 * * * * /usr/bin/php /path/to/app/system/cron/auth_purge.php
 *
 * Policy errori (loud-debug + fail-open per manutenzione)
 *   Ogni fase isolata in try/catch: una fase rotta non blocca le altre.
 *   In dev la prima eccezione viene rilanciata a fine script.
 * --------------------------------------------------------------------
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "auth_purge: CLI only\n";
    exit;
}

require_once dirname(__DIR__) . '/bootstrap.php';

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
        Logger::error("auth_purge[$label] failed: " . $e->getMessage(), Logger::throwableContext($e, true));
        $errors[] = ['phase' => $label, 'message' => $e->getMessage()];
        $report[$label] = 'error';
    }
};

$run('jwt_blacklist',  function () { JwtBlacklistModel::purgeExpired(); return 'ok'; });
$run('magic_links',    function () { MagicLinkModel::purgeExpired();    return 'ok'; });
$run('refresh_tokens', function () { RefreshTokenModel::purgeExpired(); return 'ok'; });

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
        // Niente TOCTOU is_file: filemtime() ritorna false se il file e' sparito
        // o non e' un file regolare. Risparmia un syscall stat() per entry.
        $mtime = @filemtime($path);
        if ($mtime === false) continue;
        if ($mtime < $cutoff && @unlink($path)) {
            $deleted++;
        }
    }
    closedir($dh);
    return $deleted;
});

$report['finished_at'] = date('c');
$report['errors']      = $errors;
$ok = empty($errors);

Logger::debug('auth_purge completed', $report);

foreach ($report as $k => $v) {
    if (is_array($v)) $v = json_encode($v);
    echo str_pad($k, 18) . ' : ' . $v . PHP_EOL;
}

if (Env::isDev() && !$ok) {
    throw new RuntimeException('auth_purge: ' . $errors[0]['message']);
}

exit($ok ? 0 : 1);
