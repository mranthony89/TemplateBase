<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * Refresh tokens persistence with rotation support.
 * Schema: see database/auth_module.sql
 */
final class RefreshTokenModel
{
    public static function issue(int $userId, string $jti, int $expiresAt): void
    {
        Database::insert(
            'INSERT INTO refresh_tokens (user_id, jti, expires_at, created_at) VALUES (?, ?, FROM_UNIXTIME(?), NOW())',
            [$userId, $jti, $expiresAt]
        );
    }

    public static function isValid(int $userId, string $jti): bool
    {
        $row = Database::fetchOne(
            'SELECT id FROM refresh_tokens WHERE user_id = ? AND jti = ? AND revoked_at IS NULL AND expires_at > NOW() LIMIT 1',
            [$userId, $jti]
        );
        return !empty($row);
    }

    public static function revoke(int $userId, string $jti): void
    {
        Database::execute(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND jti = ?',
            [$userId, $jti]
        );
    }

    public static function revokeAllForUser(int $userId): void
    {
        Database::execute(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
            [$userId]
        );
    }

    public static function rotate(int $userId, string $oldJti, string $newJti, int $newExpiresAt): bool
    {
        if (!self::isValid($userId, $oldJti)) return false;
        self::revoke($userId, $oldJti);
        self::issue($userId, $newJti, $newExpiresAt);
        return true;
    }

    public static function purgeExpired(): void
    {
        Database::execute('DELETE FROM refresh_tokens WHERE expires_at < NOW()');
    }
}
