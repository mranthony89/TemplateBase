<?php
if (!defined('SECURE_ACCESS')) die;

final class JwtBlacklistModel
{
    public static function add(string $jti, int $exp): void
    {
        Database::insert(
            'INSERT IGNORE INTO jwt_blacklist (jti, expires_at, created_at) VALUES (?, FROM_UNIXTIME(?), NOW())',
            [$jti, $exp]
        );
    }

    public static function isBlacklisted(string $jti): bool
    {
        $row = Database::fetchOne(
            'SELECT 1 AS x FROM jwt_blacklist WHERE jti = ? AND expires_at > NOW() LIMIT 1',
            [$jti]
        );
        return !empty($row);
    }

    public static function purgeExpired(): void
    {
        Database::execute('DELETE FROM jwt_blacklist WHERE expires_at < NOW()');
    }
}
