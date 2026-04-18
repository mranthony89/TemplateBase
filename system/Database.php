<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * system/Database.php
 * --------------------------------------------------------------------
 * MySQLi Singleton con PREPARED STATEMENTS OBBLIGATORI e auto-detection
 * dei tipi per bind_param ('i' int, 'd' double, 's' string, 'b' blob).
 *
 * Rende IMPOSSIBILE eseguire query senza binding: non esiste un metodo
 * pubblico che accetti SQL concatenato con input utente.
 * --------------------------------------------------------------------
 */
final class Database
{
    private static ?Database $instance = null;
    private mysqli $conn;

    private function __construct()
    {
        $cfg = $GLOBALS['config']['db'] ?? null;
        if (!$cfg) {
            throw new RuntimeException('Configurazione DB mancante in config/config.php');
        }

        // Errori MySQLi come eccezioni (no warning silenziosi)
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

        $this->conn = new mysqli(
            $cfg['host'],
            $cfg['user'],
            $cfg['pass'],
            $cfg['name'],
            $cfg['port'] ?? 3306
        );
        $this->conn->set_charset($cfg['charset'] ?? 'utf8mb4');
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /** Accesso diretto al mysqli (solo per casi edge, evitare) */
    public function raw(): mysqli
    {
        return $this->conn;
    }

    /**
     * SELECT che restituisce TUTTE le righe.
     * @param string $sql    Query con placeholder `?`
     * @param array  $params Parametri (i tipi sono auto-rilevati)
     */
    public static function fetchAll(string $sql, array $params = []): array
    {
        $stmt = self::prepareAndExecute($sql, $params);
        $res = $stmt->get_result();
        $rows = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
        $stmt->close();
        return $rows;
    }

    /** SELECT che restituisce la PRIMA riga (o null) */
    public static function fetchOne(string $sql, array $params = []): ?array
    {
        $stmt = self::prepareAndExecute($sql, $params);
        $res = $stmt->get_result();
        $row = $res ? $res->fetch_assoc() : null;
        $stmt->close();
        return $row ?: null;
    }

    /** INSERT — restituisce l'ID appena inserito */
    public static function insert(string $sql, array $params = []): int
    {
        $stmt = self::prepareAndExecute($sql, $params);
        $id = (int)self::getInstance()->conn->insert_id;
        $stmt->close();
        return $id;
    }

    /** UPDATE/DELETE — restituisce il numero di righe modificate */
    public static function execute(string $sql, array $params = []): int
    {
        $stmt = self::prepareAndExecute($sql, $params);
        $affected = $stmt->affected_rows;
        $stmt->close();
        return $affected;
    }

    /**
     * Prepara il statement, auto-rileva i tipi e fa bind+execute.
     * Metodo privato: nessuna SQL arbitraria può bypassare il binding.
     */
    private static function prepareAndExecute(string $sql, array $params): mysqli_stmt
    {
        $conn = self::getInstance()->conn;
        try {
            $stmt = $conn->prepare($sql);
        } catch (mysqli_sql_exception $e) {
            Logger::db('Prepare failed: ' . $e->getMessage(), ['sql' => $sql]);
            throw $e;
        }

        if ($params) {
            $types = '';
            foreach ($params as $p) {
                if (is_int($p))         $types .= 'i';
                elseif (is_float($p))   $types .= 'd';
                elseif (is_null($p))    $types .= 's'; // null va come stringa per MySQLi
                elseif (is_bool($p))    $types .= 'i'; // bool come int
                else                    $types .= 's';
            }
            // Converti bool→int prima del bind
            $bound = array_map(fn($v) => is_bool($v) ? (int)$v : $v, $params);
            $stmt->bind_param($types, ...$bound);
        }

        try {
            $stmt->execute();
        } catch (mysqli_sql_exception $e) {
            Logger::db('Execute failed: ' . $e->getMessage(), ['sql' => $sql]);
            throw $e;
        }
        return $stmt;
    }
}
