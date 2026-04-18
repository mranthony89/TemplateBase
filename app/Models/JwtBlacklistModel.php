<?php
if (!defined('SECURE_ACCESS')) die;

final class JwtBlacklistModel
{
    private Database $db;
    public function __construct() { $this->db = Database::getInstance(); }

    public function add(string $jti, int $exp): void
    {
        $this->db->insert(
            'INSERT IGNORE INTO jwt_blacklist (jti, expires_at, created_at) VALUES (?, FROM_UNIXTIME(?), NOW())',
            [$jti, $exp]
        );
    }

    public function isBlacklisted(string $jti): bool
    {
        $row = $this->db->fetchOne(
            'SELECT 1 AS x FROM jwt_blacklist WHERE jti = ? AND expires_at > NOW() LIMIT 1',
            [$jti]
        );
        return !empty($row);
    }

    public function purgeExpired(): void
    {
        $this->db->execute('DELETE FROM jwt_blacklist WHERE expires_at < NOW()');
    }
}
