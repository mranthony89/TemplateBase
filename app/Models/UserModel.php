<?php
if (!defined('SECURE_ACCESS')) die;

final class UserModel
{
    public static function findByIdForUser(int $targetId, int $currentUserId): ?array
    {
        return Database::fetchOne(
            'SELECT id, email, created_at FROM users WHERE id = ? AND id = ? LIMIT 1',
            [$targetId, $currentUserId]
        );
    }

    public static function findById(int $id, bool $skipRls = false, ?int $currentUserId = null): ?array
    {
        if (!$skipRls) {
            if ($currentUserId === null || $currentUserId !== $id) {
                Logger::security('UserModel::findById RLS blocked', [
                    'target_id'       => $id,
                    'current_user_id' => $currentUserId,
                ]);
                return null;
            }
        }
        return Database::fetchOne(
            'SELECT id, email, created_at, totp_enabled FROM users WHERE id = ? LIMIT 1',
            [$id]
        );
    }

    public static function findByEmail(string $email): ?array
    {
        return Database::fetchOne(
            'SELECT id, email, created_at FROM users WHERE email = ? LIMIT 1',
            [$email]
        );
    }

    public static function exists(string $email): bool
    {
        $row = Database::fetchOne(
            'SELECT 1 AS e FROM users WHERE email = ? LIMIT 1',
            [$email]
        );
        return $row !== null;
    }

    public static function create(string $email, string $plainPassword): int
    {
        $opts = [];
        if (defined('PASSWORD_COST')) $opts['cost'] = (int)PASSWORD_COST;
        $algo = defined('PASSWORD_ALGO') ? PASSWORD_ALGO : PASSWORD_DEFAULT;
        $hash = password_hash($plainPassword, $algo, $opts);
        return Database::insert(
            'INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, NOW())',
            [$email, $hash]
        );
    }

    public static function verifyCredentials(string $email, string $plainPassword): ?array
    {
        $user = Database::fetchOne(
            'SELECT id, email, password_hash, totp_enabled FROM users WHERE email = ? LIMIT 1',
            [$email]
        );
        if (!$user) {
            password_verify($plainPassword, '$2y$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidiu');
            return null;
        }
        if (!password_verify($plainPassword, $user['password_hash'])) {
            return null;
        }
        unset($user['password_hash']);
        return $user;
    }

    public static function updateEmail(int $userId, string $newEmail): int
    {
        return Database::execute(
            'UPDATE users SET email = ? WHERE id = ?',
            [$newEmail, $userId]
        );
    }

    public static function updatePassword(int $userId, string $newPlainPassword): bool
    {
        $opts = [];
        if (defined('PASSWORD_COST')) $opts['cost'] = (int)PASSWORD_COST;
        $algo = defined('PASSWORD_ALGO') ? PASSWORD_ALGO : PASSWORD_DEFAULT;
        $hash = password_hash($newPlainPassword, $algo, $opts);
        $affected = Database::execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            [$hash, $userId]
        );
        return $affected > 0;
    }

    public static function delete(int $userId): bool
    {
        $affected = Database::execute(
            'DELETE FROM users WHERE id = ?',
            [$userId]
        );
        return $affected > 0;
    }

    /* ---- Auth-module helpers ---- */

    /**
     * Internal lookup bypassing RLS — only for auth flows where the caller
     * is establishing identity (login, magic-link, JWT validation).
     * NEVER expose this method to controllers performing user-data reads.
     */
    public static function findByIdInternal(int $id): ?array
    {
        return Database::fetchOne(
            'SELECT id, email, totp_enabled FROM users WHERE id = ? LIMIT 1',
            [$id]
        );
    }

    public static function setTotpSecret(int $userId, string $secret): void
    {
        Database::execute(
            'UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?',
            [$secret, $userId]
        );
    }

    public static function enableTotp(int $userId): void
    {
        Database::execute(
            'UPDATE users SET totp_enabled = 1 WHERE id = ?',
            [$userId]
        );
    }

    public static function disableTotp(int $userId): void
    {
        Database::execute(
            'UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?',
            [$userId]
        );
    }

    public static function hasTotp(int $userId): bool
    {
        $row = Database::fetchOne(
            'SELECT totp_enabled FROM users WHERE id = ? LIMIT 1',
            [$userId]
        );
        return !empty($row) && (int)$row['totp_enabled'] === 1;
    }

    public static function getTotpSecret(int $userId): ?string
    {
        $row = Database::fetchOne(
            'SELECT totp_secret FROM users WHERE id = ? LIMIT 1',
            [$userId]
        );
        return $row['totp_secret'] ?? null;
    }
}
