<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * JwtBlacklistModel
 * --------------------------------------------------------------------
 * Persistent storage for revoked JWT IDs (JTI). Backs Jwt::isBlacklisted()
 * and Jwt::blacklist(). Driver selected via the JWT_BLACKLIST_DRIVER
 * constant (currently only 'database' is implemented).
 *
 * Schema: see database/auth_module.sql (table `jwt_blacklist`).
 *
 * Error policy
 *   Every DB call is wrapped in try/catch:
 *     - Logger::error always records the failure (file, line, sql),
 *     - in development the exception is re-thrown so the front-controller
 *       handler can surface it (loud-debug),
 *     - in production add() and purgeExpired() degrade silently to keep
 *       the auth flow alive (a single failed insert must not 500 the API),
 *     - isBlacklisted() in production returns TRUE on failure: fail-closed
 *       (treat as blacklisted) so a broken DB cannot let a revoked token
 *       slip through.
 * --------------------------------------------------------------------
 */
final class JwtBlacklistModel
{
    private static function driver(): string
    {
        return defined('JWT_BLACKLIST_DRIVER') ? (string)JWT_BLACKLIST_DRIVER : 'database';
    }

    private static function ensureDriverSupported(): void
    {
        $d = self::driver();
        if ($d !== 'database') {
            $msg = "JWT_BLACKLIST_DRIVER='$d' non supportato. Solo 'database' è implementato.";
            Logger::error($msg);
            throw new RuntimeException($msg);
        }
    }

    private static function isDev(): bool
    {
        return defined('APP_ENV') && APP_ENV === 'development';
    }

    public static function add(string $jti, int $expiresAt): void
    {
        self::ensureDriverSupported();
        if ($jti === '' || $expiresAt <= 0) {
            $msg = 'JwtBlacklistModel::add invalid args';
            Logger::error($msg, ['jti_len' => strlen($jti), 'exp' => $expiresAt]);
            if (self::isDev()) throw new InvalidArgumentException($msg);
            return;
        }
        try {
            Database::insert(
                'INSERT IGNORE INTO jwt_blacklist (jti, expires_at, created_at)
                 VALUES (?, FROM_UNIXTIME(?), NOW())',
                [$jti, $expiresAt]
            );
        } catch (\Throwable $e) {
            Logger::error('JwtBlacklistModel::add failed: ' . $e->getMessage(), [
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);
            if (self::isDev()) throw $e;
        }
    }

    public static function isBlacklisted(string $jti): bool
    {
        self::ensureDriverSupported();
        if ($jti === '') return false;
        try {
            $row = Database::fetchOne(
                'SELECT 1 AS x FROM jwt_blacklist
                 WHERE jti = ? AND expires_at > NOW() LIMIT 1',
                [$jti]
            );
            return !empty($row);
        } catch (\Throwable $e) {
            Logger::error('JwtBlacklistModel::isBlacklisted failed: ' . $e->getMessage(), [
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);
            if (self::isDev()) throw $e;
            // fail-closed in production: tratta come blacklistato
            return true;
        }
    }

    public static function purgeExpired(): void
    {
        self::ensureDriverSupported();
        try {
            Database::execute('DELETE FROM jwt_blacklist WHERE expires_at < NOW()');
        } catch (\Throwable $e) {
            Logger::error('JwtBlacklistModel::purgeExpired failed: ' . $e->getMessage(), [
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ]);
            if (self::isDev()) throw $e;
        }
    }
}
