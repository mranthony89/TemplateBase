<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * MagicLinkModel
 * --------------------------------------------------------------------
 * Passwordless magic links.
 *   - Plain token: 32 random bytes (bin2hex -> 64 hex chars), inviato solo
 *     via email.
 *   - DB store: sha256(token_plain). Single-use enforcement via
 *     `UPDATE ... WHERE used_at IS NULL` con affected_rows check.
 *   - ip_hash: HMAC-SHA256(ip, auth.pepper) se pepper presente, altrimenti
 *     sha256(ip) backward-compatible. Senza pepper il valore e' una
 *     pseudonymization debole (rainbow-table su IPv4 in secondi su GPU).
 * --------------------------------------------------------------------
 */
final class MagicLinkModel
{
    private static function ipHash(string $ip): string
    {
        $pepper = (string)Config::get('auth.pepper', '');
        return $pepper !== ''
            ? hash_hmac('sha256', $ip, $pepper)
            : hash('sha256', $ip);
    }

    public static function create(int $userId, string $tokenPlain, int $expiresAt, string $ip): void
    {
        $hash = hash('sha256', $tokenPlain);
        Database::insert(
            'INSERT INTO magic_links (user_id, token_hash, expires_at, ip_hash, created_at)
             VALUES (?, ?, FROM_UNIXTIME(?), ?, NOW())',
            [$userId, $hash, $expiresAt, self::ipHash($ip)]
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
