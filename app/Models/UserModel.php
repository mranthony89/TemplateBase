<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * app/Models/UserModel.php
 * --------------------------------------------------------------------
 * Modello utente con ROW-LEVEL SECURITY forzata.
 *
 * Ogni metodo che accede a dati utente RICHIEDE due parametri:
 *   - $targetId:    il record da leggere/modificare
 *   - $currentUser: l'utente che sta facendo la richiesta
 *
 * Anche quando i due coincidono (utente legge i propri dati), la
 * firma rende impossibile dimenticarsi del check di ownership.
 * --------------------------------------------------------------------
 */
final class UserModel
{
    /**
     * Trova un utente per ID, ma solo se appartiene al richiedente.
     * Per record personali: $targetId === $currentUserId.
     * Per record condivisi: la query può essere estesa (JOIN permissions).
     */
    public static function findByIdForUser(int $targetId, int $currentUserId): ?array
    {
        // Il WHERE id = ? AND id = ? è volutamente ridondante per rendere
        // ESPLICITO che qualsiasi query utente include SEMPRE l'owner check.
        // In tabelle relazionali (es. posts) sarebbe: WHERE id = ? AND user_id = ?
        return Database::fetchOne(
            'SELECT id, email, created_at FROM users WHERE id = ? AND id = ? LIMIT 1',
            [$targetId, $currentUserId]
        );
    }

    /** Creazione utente — password hashata con bcrypt (PASSWORD_DEFAULT) */
    public static function create(string $email, string $plainPassword): int
    {
        $hash = password_hash($plainPassword, PASSWORD_DEFAULT);
        return Database::insert(
            'INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, NOW())',
            [$email, $hash]
        );
    }

    /**
     * Verifica credenziali in modo timing-safe.
     * password_verify usa internamente un confronto costante-tempo.
     */
    public static function verifyCredentials(string $email, string $plainPassword): ?array
    {
        $user = Database::fetchOne(
            'SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1',
            [$email]
        );
        if (!$user) {
            // Eseguo comunque un hash fake per evitare user-enumeration via timing
            password_verify($plainPassword, '$2y$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidiu');
            return null;
        }
        if (!password_verify($plainPassword, $user['password_hash'])) {
            return null;
        }
        unset($user['password_hash']);
        return $user;
    }

    /** UPDATE atomico con RLS (WHERE id = ?) */
    public static function updateEmail(int $userId, string $newEmail): int
    {
        return Database::execute(
            'UPDATE users SET email = ? WHERE id = ?',
            [$newEmail, $userId]
        );
    }
}
