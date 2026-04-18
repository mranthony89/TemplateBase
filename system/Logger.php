<?php
if (!defined('SECURE_ACCESS')) die;

final class Logger
{
    public const SECURITY = 'security';
    public const DEBUG    = 'debug';
    public const DB       = 'db';
    public const ERRORS   = 'errors';

    public static function security(string $message, array $context = []): void
    {
        self::write(self::SECURITY, 'SECURITY', $message, $context);
    }

    public static function debug(string $message, array $context = []): void
    {
        if (defined('APP_ENV') && APP_ENV !== 'development') return;
        self::write(self::DEBUG, 'DEBUG', $message, $context);
    }

    public static function db(string $message, array $context = []): void
    {
        self::write(self::DB, 'DB', $message, $context);
    }

    public static function error(string $message, array $context = []): void
    {
        self::write(self::ERRORS, 'ERROR', $message, $context);
    }

    private static function maskIp(string $ip): string
    {
        if (!defined('LOG_IP_MASK') || LOG_IP_MASK !== true) return $ip;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            $parts[3] = 'xxx';
            return implode('.', $parts);
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            $kept  = array_slice($parts, 0, 4);
            return implode(':', $kept) . ':xxxx:xxxx:xxxx:xxxx';
        }
        return 'xxx';
    }

    private static function hashEmail(string $email): string
    {
        $algo = defined('LOG_EMAIL_HASH_ALGO') ? LOG_EMAIL_HASH_ALGO : 'sha256';
        return hash($algo, strtolower(trim($email)));
    }

    private static function sanitizeContext(array $context, string $category): array
    {
        $keepFullIp = ($category === self::SECURITY)
            && !empty($context['gdpr_sensitive']);
        foreach ($context as $k => $v) {
            if (!is_string($v)) continue;
            $lk = strtolower((string)$k);
            if (in_array($lk, ['email', 'user_email', 'mail'], true)) {
                $context[$k] = 'sha256:' . self::hashEmail($v);
            } elseif (in_array($lk, ['ip', 'user_ip', 'client_ip', 'remote_addr'], true)) {
                $context[$k] = $keepFullIp ? ($v . ' (gdpr_sensitive=1)') : self::maskIp($v);
            }
        }
        return $context;
    }

    private static function write(string $category, string $level, string $message, array $context): void
    {
        $dir = LOGS_PATH . '/' . $category;
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
            @file_put_contents($dir . '/.htaccess', "Require all denied\n");
        }

        $date = (new DateTimeImmutable('now'))->format('Y-m-d');
        $file = $dir . '/' . $category . '-' . $date . '.log';

        $context = self::sanitizeContext($context, $category);
        $ip = self::clientIp();
        $ipForLine = ($category === self::SECURITY && !empty($context['gdpr_sensitive']))
            ? $ip
            : self::maskIp($ip);

        $line = sprintf(
            "[%s] [%s] [%s] %s%s\n",
            (new DateTimeImmutable('now'))->format('Y-m-d H:i:s'),
            $level,
            $ipForLine,
            $message,
            $context ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : ''
        );

        @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }

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
