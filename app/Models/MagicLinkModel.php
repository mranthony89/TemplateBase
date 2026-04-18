<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * Passwordless magic links. The token plaintext is sent only via email;
 * the database stores its sha256 hash. Atomic single-use is enforced by
 * UPDATE ... WHERE used_at IS NULL.
 */
final class MagicLinkModel
{
    private Database $db;
    public function __construct() { $this->db = Database::getInstance(); }

    public function create(int $userId, string $tokenPlain, int $expiresAt, string $ip): void
    {
        $hash = hash('sha256', $tokenPlain);
        $this->db->insert(
            'INSERT INTO magic_links (user_id, token_hash, expires_at, ip_hash, created_at)
             VALUES (?, ?, FROM_UNIXTIME(?), ?, NOW())',
            [$userId, $hash, $expiresAt, hash('sha256', $ip)]
        );
    }

    public function consume(string $tokenPlain): ?int
    {
        $hash = hash('sha256', $tokenPlain);
        $row = $this->db->fetchOne(
            'SELECT id, user_id FROM magic_links
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()
             LIMIT 1',
            [$hash]
        );
        if (!$row) return null;

        $affected = $this->db->execute(
            'UPDATE magic_links SET used_at = NOW() WHERE id = ? AND used_at IS NULL',
            [(int)$row['id']]
        );
        if ($affected !== 1) return null;

        return (int)$row['user_id'];
    }

    public function purgeExpired(): void
    {
        $this->db->execute('DELETE FROM magic_links WHERE expires_at < NOW() OR used_at IS NOT NULL');
    }
}
