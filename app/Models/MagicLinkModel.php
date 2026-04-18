<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * Passwordless magic links. Plaintext token sent only via email;
 * DB stores its sha256 hash. Single-use via UPDATE ... WHERE used_at IS NULL.
 */
final class MagicLinkModel
{
    public static function create(int $userId, string $tokenPlain, int $expiresAt, string $ip): void
    {
        $hash = hash('sha256', $tokenPlain);
        Database::insert(
            'INSERT INTO magic_links (user_id, token_hash, expires_at, ip_hash, created_at)
             VALUES (?, ?, FROM_UNIXTIME(?), ?, NOW())',
            [$userId, $hash, $expiresAt, hash('sha256', $ip)]
        );
    }

    public static function consume(string $tokenPlain): ?int
    {
        $hash = hash('sha256', $tokenPlain);
        $row = Database::fetchOne(
            'SELECT id, user_id FROM magic_links
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()
             LIMIT 1',
            [$hash]
        );
        if (!$row) return null;

        $affected = Database::execute(
            'UPDATE magic_links SET used_at = NOW() WHERE id = ? AND used_at IS NULL',
            [(int)$row['id']]
        );
        if ($affected !== 1) return null;

        return (int)$row['user_id'];
    }

    public static function purgeExpired(): void
    {
        Database::execute('DELETE FROM magic_links WHERE expires_at < NOW() OR used_at IS NOT NULL');
    }
}
