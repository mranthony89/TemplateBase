<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * system/Logger.php
 * --------------------------------------------------------------------
 * Logging categorizzato con rotazione giornaliera.
 * Struttura:
 *   /logs/security/security-YYYY-MM-DD.log   → eventi CSRF, login fail, hijacking
 *   /logs/debug/debug-YYYY-MM-DD.log         → log applicativi di debug
 *   /logs/db/db-YYYY-MM-DD.log               → query lente / errori DB
 *   /logs/errors/error-YYYY-MM-DD.log        → PHP errors/exceptions/fatal
 *
 * Evoluzione del dual-log di Repo A + classe OOP di Repo B, con
 * l'aggiunta REQUIRED di rotazione giornaliera e sottocartelle.
 * --------------------------------------------------------------------
 */
final class Logger
{
    public const SECURITY = 'security';
    public const DEBUG    = 'debug';
    public const DB       = 'db';
    public const ERRORS   = 'errors';

    /** Scrive un evento di sicurezza (CSRF, login fail, session hijacking...) */
    public static function security(string $message, array $context = []): void
    {
        self::write(self::SECURITY, 'SECURITY', $message, $context);
    }

    /** Debug applicativo (disattivabile in produzione tramite APP_ENV) */
    public static function debug(string $message, array $context = []): void
    {
        if (defined('APP_ENV') && APP_ENV !== 'development') return;
        self::write(self::DEBUG, 'DEBUG', $message, $context);
    }

    /** Query lente, errori DB, deadlock */
    public static function db(string $message, array $context = []): void
    {
        self::write(self::DB, 'DB', $message, $context);
    }

    /** Errori PHP / Exception / Fatal (chiamato da bootstrap.php) */
    public static function error(string $message, array $context = []): void
    {
        self::write(self::ERRORS, 'ERROR', $message, $context);
    }

    /**
     * Scrittura atomica su file con rotazione giornaliera.
     * Nome file: {categoria}-{YYYY-MM-DD}.log via DateTime (no conflitti timezone).
     */
    private static function write(string $category, string $level, string $message, array $context): void
    {
        $dir = LOGS_PATH . '/' . $category;

        // Lazy-create directory con .htaccess protettivo se mancante
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
            @file_put_contents($dir . '/.htaccess', "Require all denied\n");
        }

        $date = (new DateTimeImmutable('now'))->format('Y-m-d');
        $file = $dir . '/' . $category . '-' . $date . '.log';

        $line = sprintf(
            "[%s] [%s] [%s] %s%s\n",
            (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
            $level,
            self::clientIp(),
            $message,
            $context ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : ''
        );

        // FILE_APPEND | LOCK_EX → scritture concorrenti sicure (no race condition)
        @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Client IP con supporto proxy fidati (fix vuln 3.3 auto-rilevata in Repo A).
     * X-Forwarded-For è accettato SOLO se la richiesta viene da un proxy
     * elencato in TRUSTED_PROXIES.
     */
    private static function clientIp(): string
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $trusted = defined('TRUSTED_PROXIES') ? TRUSTED_PROXIES : [];
        if (in_array($remote, $trusted, true) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
            return filter_var($parts[0], FILTER_VALIDATE_IP) ?: $remote;
        }
        return $remote;
    }
}
