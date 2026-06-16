<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * UserModel
 * --------------------------------------------------------------------
 * Tutti i metodi sono statici e usano prepared statements via Database::*.
 * Le SELECT/UPDATE che leggono dati personali esigono un currentUserId
 * (Row-Level Security esplicita). Le helper marcate "Internal" sono
 * pensate solo per flussi di autenticazione (login, magic-link, JWT).
 *
 * Loud-debug: ogni catch logga via Logger::error e in dev ri-lancia.
 * --------------------------------------------------------------------
 */
final class UserModel
{
    private static function dbCatch(\Throwable $e, string $op): void
    {
        Logger::error("UserModel::$op DB error: " . $e->getMessage(), Logger::throwableContext($e));
        if (Env::isDev()) throw $e;
    }

    public static function findByIdForUser(int $targetId, int $currentUserId): ?array
    {
        try {
            return Database::fetchOne(
                'SELECT id, email, created_at FROM users WHERE id = ? AND id = ? LIMIT 1',
                [$targetId, $currentUserId]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'findByIdForUser'); return null; }
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
        try {
            return Database::fetchOne(
                'SELECT id, email, created_at, totp_enabled FROM users WHERE id = ? LIMIT 1',
                [$id]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'findById'); return null; }
    }

    public static function findByEmail(string $email): ?array
    {
        try {
            return Database::fetchOne(
                'SELECT id, email, created_at FROM users WHERE email = ? LIMIT 1',
                [$email]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'findByEmail'); return null; }
    }

    public static function exists(string $email): bool
    {
        try {
            $row = Database::fetchOne(
                'SELECT 1 AS e FROM users WHERE email = ? LIMIT 1',
                [$email]
            );
            return $row !== null;
        } catch (\Throwable $e) { self::dbCatch($e, 'exists'); return false; }
    }

    public static function create(string $email, string $plainPassword): int
    {
        $opts = [];
        if (defined('PASSWORD_COST')) $opts['cost'] = (int)PASSWORD_COST;
        $algo = defined('PASSWORD_ALGO') ? PASSWORD_ALGO : PASSWORD_DEFAULT;
        $hash = password_hash($plainPassword, $algo, $opts);
        try {
            return Database::insert(
                'INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, NOW())',
                [$email, $hash]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'create'); return 0; }
    }

    public static function verifyCredentials(string $email, string $plainPassword): ?array
    {
        try {
            $user = Database::fetchOne(
                'SELECT id, email, password_hash, totp_enabled FROM users WHERE email = ? LIMIT 1',
                [$email]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'verifyCredentials'); return null; }

        if (!$user) {
            // costante temporale: anti user-enumeration via timing
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
        try {
            return Database::execute(
                'UPDATE users SET email = ? WHERE id = ?',
                [$newEmail, $userId]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'updateEmail'); return 0; }
    }

    public static function updatePassword(int $userId, string $newPlainPassword): bool
    {
        $opts = [];
        if (defined('PASSWORD_COST')) $opts['cost'] = (int)PASSWORD_COST;
        $algo = defined('PASSWORD_ALGO') ? PASSWORD_ALGO : PASSWORD_DEFAULT;
        $hash = password_hash($newPlainPassword, $algo, $opts);
        try {
            $affected = Database::execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                [$hash, $userId]
            );
            return $affected > 0;
        } catch (\Throwable $e) { self::dbCatch($e, 'updatePassword'); return false; }
    }

    public static function delete(int $userId): bool
    {
        try {
            $affected = Database::execute(
                'DELETE FROM users WHERE id = ?',
                [$userId]
            );
            return $affected > 0;
        } catch (\Throwable $e) { self::dbCatch($e, 'delete'); return false; }
    }

    /* ============================================================
     * Auth-module helpers (uso server-side per flussi auth)
     * ============================================================ */

    public static function findByIdInternal(int $id): ?array
    {
        if ($id <= 0) return null;
        try {
            return Database::fetchOne(
                'SELECT id, email, totp_enabled FROM users WHERE id = ? LIMIT 1',
                [$id]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'findByIdInternal'); return null; }
    }

    public static function setTotpSecret(int $userId, string $secret): void
    {
        if ($userId <= 0 || $secret === '') {
            $msg = 'UserModel::setTotpSecret args invalidi';
            Logger::error($msg, ['user_id' => $userId]);
            if (Env::isDev()) throw new InvalidArgumentException($msg);
            return;
        }
        try {
            Database::execute(
                'UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?',
                [$secret, $userId]
            );
        } catch (\Throwable $e) { self::dbCatch($e, 'setTotpSecret'); }
    }

    public static function enableTotp(int $userId): void
    {
        if ($userId <= 0) return;
        try {
            Database::execute('UPDATE users SET totp_enabled = 1 WHERE id = ?', [$userId]);
        } catch (\Throwable $e) { self::dbCatch($e, 'enableTotp'); }
    }

    public static function disableTotp(int $userId): void
    {
        if ($userId <= 0) return;
        try {
            Database::execute('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [$userId]);
        } catch (\Throwable $e) { self::dbCatch($e, 'disableTotp'); }
    }

    public static function hasTotp(int $userId): bool
    {
        if ($userId <= 0) return false;
        try {
            $row = Database::fetchOne('SELECT totp_enabled FROM users WHERE id = ? LIMIT 1', [$userId]);
            return !empty($row) && (int)$row['totp_enabled'] === 1;
        } catch (\Throwable $e) { self::dbCatch($e, 'hasTotp'); return false; }
    }

    public static function getTotpSecret(int $userId): ?string
    {
        if ($userId <= 0) return null;
        try {
            $row = Database::fetchOne('SELECT totp_secret FROM users WHERE id = ? LIMIT 1', [$userId]);
            return $row['totp_secret'] ?? null;
        } catch (\Throwable $e) { self::dbCatch($e, 'getTotpSecret'); return null; }
    }
}
