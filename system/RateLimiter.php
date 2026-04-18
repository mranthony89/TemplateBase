<?php
if (!defined('SECURE_ACCESS')) die;

final class RateLimiter
{
    private static function dir(): string
    {
        $dir = LOGS_PATH . '/ratelimit';
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
            @file_put_contents($dir . '/.htaccess', "Require all denied\n");
        }
        return $dir;
    }

    private static function file(string $key): string
    {
        $safe = hash('sha256', $key);
        return self::dir() . '/' . $safe . '.json';
    }

    public static function throttle(string $key, ?int $max = null, ?int $window = null): bool
    {
        $max    = $max    ?? (defined('RATE_LIMIT_MAX')    ? RATE_LIMIT_MAX    : 60);
        $window = $window ?? (defined('RATE_LIMIT_WINDOW') ? RATE_LIMIT_WINDOW : 60);

        $file = self::file($key);
        $now  = time();

        $fp = fopen($file, 'c+');
        if (!$fp) return true;
        flock($fp, LOCK_EX);

        $raw = stream_get_contents($fp);
        $data = $raw ? json_decode($raw, true) : null;
        if (!is_array($data) || !isset($data['start']) || ($now - $data['start']) >= $window) {
            $data = ['start' => $now, 'count' => 0];
        }
        $data['count']++;

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        return $data['count'] <= $max;
    }

    public static function remaining(string $key): int
    {
        $max  = defined('RATE_LIMIT_MAX') ? RATE_LIMIT_MAX : 60;
        $file = self::file($key);
        if (!is_file($file)) return $max;
        $data = json_decode((string)@file_get_contents($file), true);
        $used = (int)($data['count'] ?? 0);
        return max(0, $max - $used);
    }

    public static function reset(string $key): void
    {
        $file = self::file($key);
        if (is_file($file)) @unlink($file);
    }
}
