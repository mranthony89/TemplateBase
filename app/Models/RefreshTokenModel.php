<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * Refresh tokens persistence with rotation support.
 * Schema: see database/auth_module.sql
 */
final class RefreshTokenModel
{
    private Database $db;
    public function __construct() { $this->db = Database::getInstance(); }

    public function issue(int $userId, string $jti, int $expiresAt): void
    {
        $this->db->insert(
            'INSERT INTO refresh_tokens (user_id, jti, expires_at, created_at) VALUES (?, ?, FROM_UNIXTIME(?), NOW())',
            [$userId, $jti, $expiresAt]
        );
    }

    public function isValid(int $userId, string $jti): bool
    {
        $row = $this->db->fetchOne(
            'SELECT id FROM refresh_tokens WHERE user_id = ? AND jti = ? AND revoked_at IS NULL AND expires_at > NOW() LIMIT 1',
            [$userId, $jti]
        );
        return !empty($row);
    }

    public function revoke(int $userId, string $jti): void
    {
        $this->db->execute(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND jti = ?',
            [$userId, $jti]
        );
    }

    public function revokeAllForUser(int $userId): void
    {
        $this->db->execute(
            'UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL',
            [$userId]
        );
    }

    public function rotate(int $userId, string $oldJti, string $newJti, int $newExpiresAt): bool
    {
        if (!$this->isValid($userId, $oldJti)) return false;
        $this->revoke($userId, $oldJti);
        $this->issue($userId, $newJti, $newExpiresAt);
        return true;
    }

    public function purgeExpired(): void
    {
        $this->db->execute('DELETE FROM refresh_tokens WHERE expires_at < NOW()');
    }
}
