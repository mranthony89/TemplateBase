<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * JwtBlacklistModel
 * --------------------------------------------------------------------
 * Persistence dei JTI revocati. Backs Jwt::isBlacklisted() e Jwt::blacklist().
 * Driver selezionato via JWT_BLACKLIST_DRIVER (oggi solo 'database').
 *
 * Error policy (loud-debug + fail-closed in prod su isBlacklisted):
 *   - ogni Throwable loggato con Logger::throwableContext,
 *   - in dev rilanciato (front-controller mostra trace),
 *   - in prod add()/purgeExpired() degradano silenziosi,
 *   - isBlacklisted() in prod ritorna TRUE on failure: un DB rotto non
 *     deve mai lasciar passare un token revocato.
 * --------------------------------------------------------------------
 */
final class JwtBlacklistModel
{
    private static function ensureDriverSupported(): void
    {
        $d = defined('JWT_BLACKLIST_DRIVER') ? (string)JWT_BLACKLIST_DRIVER : 'database';
        if ($d !== 'database') {
            $msg = "JWT_BLACKLIST_DRIVER='$d' non supportato. Solo 'database' è implementato.";
            Logger::error($msg);
            throw new RuntimeException($msg);
        }
    }

    public static function add(string $jti, int $expiresAt): void
    {
        self::ensureDriverSupported();
        if ($jti === '' || $expiresAt <= 0) {
            $msg = 'JwtBlacklistModel::add invalid args';
            Logger::error($msg, ['jti_len' => strlen($jti), 'exp' => $expiresAt]);
            if (Env::isDev()) throw new InvalidArgumentException($msg);
            return;
        }
        try {
            Database::insert(
                'INSERT IGNORE INTO jwt_blacklist (jti, expires_at, created_at)
                 VALUES (?, FROM_UNIXTIME(?), NOW())',
                [$jti, $expiresAt]
            );
        } catch (\Throwable $e) {
            Logger::error('JwtBlacklistModel::add failed: ' . $e->getMessage(), Logger::throwableContext($e));
            if (Env::isDev()) throw $e;
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
            Logger::error('JwtBlacklistModel::isBlacklisted failed: ' . $e->getMessage(), Logger::throwableContext($e));
            if (Env::isDev()) throw $e;
            return true; // fail-closed in production
        }
    }

    public static function purgeExpired(): void
    {
        self::ensureDriverSupported();
        try {
            Database::execute('DELETE FROM jwt_blacklist WHERE expires_at < NOW()');
        } catch (\Throwable $e) {
            Logger::error('JwtBlacklistModel::purgeExpired failed: ' . $e->getMessage(), Logger::throwableContext($e));
            if (Env::isDev()) throw $e;
        }
    }
}
