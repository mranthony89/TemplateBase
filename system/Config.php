<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * system/Config.php
 * --------------------------------------------------------------------
 * Read-only wrapper around $GLOBALS['config'] (loaded by bootstrap.php
 * from config/config.php).
 *
 *   Config::get('db')                 -> intero array della sezione db
 *   Config::get('jwt.secret_key')     -> stringa annidata
 *   Config::get('mail.smtp.port', 25) -> default fallback
 *
 * È read-only by design: in shared hosting non vogliamo che codice
 * applicativo possa mutare la configurazione caricata.
 * --------------------------------------------------------------------
 */
final class Config
{
    public static function get(string $key, $default = null)
    {
        $cfg = $GLOBALS['config'] ?? null;
        if (!is_array($cfg)) {
            // Errore di programmazione: bootstrap non ha caricato la config
            $msg = 'Config::get chiamato prima del caricamento di config/config.php';
            if (class_exists('Logger', false)) {
                Logger::error($msg, ['key' => $key]);
            }
            if (defined('APP_ENV') && APP_ENV === 'development') {
                throw new RuntimeException($msg);
            }
            return $default;
        }

        // Match diretto sulla chiave top-level (anche se contiene punti veri)
        if (array_key_exists($key, $cfg)) return $cfg[$key];

        // Notazione puntata: walk dell'albero
        if (strpos($key, '.') !== false) {
            $node = $cfg;
            foreach (explode('.', $key) as $p) {
                if (!is_array($node) || !array_key_exists($p, $node)) return $default;
                $node = $node[$p];
            }
            return $node;
        }

        return $default;
    }

    /**
     * Variante "strict": se la chiave manca lancia eccezione anche in
     * production. Da usare per credenziali obbligatorie (es. JWT secret).
     */
    public static function require(string $key)
    {
        $sentinel = new \stdClass();
        $val = self::get($key, $sentinel);
        if ($val === $sentinel) {
            $msg = "Config key mancante: '$key' (controlla config/config.php).";
            if (class_exists('Logger', false)) Logger::error($msg);
            throw new RuntimeException($msg);
        }
        return $val;
    }

    public static function has(string $key): bool
    {
        $sentinel = new \stdClass();
        return self::get($key, $sentinel) !== $sentinel;
    }
}
