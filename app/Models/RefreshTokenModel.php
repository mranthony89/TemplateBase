<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * RefreshTokenModel
 * --------------------------------------------------------------------
 * Persistenza dei refresh token con rotation atomica e reuse-detection.
 * Schema: database/auth_module.sql
 *
 * Rotation atomica: l'unico modo di marcare un refresh-token come
 * revocato e' un singolo UPDATE con WHERE "AND revoked_at IS NULL AND
 * expires_at > NOW()". Solo una request concorrente puo' avere
 * affected_rows == 1: le altre ricevono 0 e rotate() ritorna false,
 * permettendo al chiamante di trattare il caso come reuse e bumpare
 * token_version. Niente TOCTOU.
 * --------------------------------------------------------------------
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

    /**
     * Rotation atomica. Ritorna true se ha rivocato esattamente UNA riga
     * e ha emesso il nuovo token; false in tutti gli altri casi (reuse,
     * gia' revocato, scaduto, race-loss).
     */
    public static function rotate(int $userId, string $oldJti, string $newJti, int $newExpiresAt): bool
    {
        $affected = Database::execute(
            'UPDATE refresh_tokens SET revoked_at = NOW()
             WHERE user_id = ? AND jti = ? AND revoked_at IS NULL AND expires_at > NOW()',
            [$userId, $oldJti]
        );
        if ($affected !== 1) {
            return false;
        }
        self::issue($userId, $newJti, $newExpiresAt);
        return true;
    }

    public static function purgeExpired(): void
    {
        Database::execute('DELETE FROM refresh_tokens WHERE expires_at < NOW()');
    }
}
