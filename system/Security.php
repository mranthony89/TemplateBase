<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * system/Security.php
 * --------------------------------------------------------------------
 * Funzione h() globale + classe CSRF + classe Validator.
 * --------------------------------------------------------------------
 */

/**
 * h() — escape HTML per output sicuro nelle view.
 * Uso: <?= h($user['name']) ?>
 * ENT_QUOTES  → escape anche di ' e "
 * ENT_HTML5   → escape compatibile con HTML5
 * UTF-8       → previene attacchi via encoding ambiguo
 */
function h($value): string
{
    if ($value === null) return '';
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * CSRF — token per sessione, validazione timing-safe.
 * Pattern preso da Repo A (OraSicurezza) + rotazione post-azione.
 */
final class CSRF
{
    private const KEY = '_csrf_token';
    private const HEADERS = ['HTTP_X_CSRF_TOKEN', 'HTTP_X_CSRF-TOKEN'];

    /** Genera (se manca) e ritorna il token corrente */
    public static function token(): string
    {
        if (empty($_SESSION[self::KEY])) {
            // random_bytes = CSPRNG crittografico. Evitare md5/uniqid (non sicuri).
            $_SESSION[self::KEY] = bin2hex(random_bytes(32)); // 64 hex char
        }
        return $_SESSION[self::KEY];
    }

    /** Campo hidden pronto per le form */
    public static function field(): string
    {
        return '<input type="hidden" name="csrf_token" value="' . h(self::token()) . '">';
    }

    /**
     * Verifica il token da: header X-CSRF-Token, campo POST csrf_token.
     * Usa hash_equals per prevenire timing attack.
     */
    public static function verify(): bool
    {
        $expected = $_SESSION[self::KEY] ?? '';
        if ($expected === '') return false;

        $provided = '';
        foreach (self::HEADERS as $h) {
            if (!empty($_SERVER[$h])) { $provided = $_SERVER[$h]; break; }
        }
        if ($provided === '') {
            $provided = $_POST['csrf_token'] ?? '';
        }

        $ok = is_string($provided) && hash_equals($expected, $provided);
        if (!$ok) {
            Logger::security('CSRF validation failed', [
                'uri'      => $_SERVER['REQUEST_URI'] ?? '',
                'method'   => $_SERVER['REQUEST_METHOD'] ?? '',
                'provided' => substr($provided, 0, 16), // log parziale, no full token
            ]);
        }
        return $ok;
    }

    /** Rotazione token dopo azione sensibile (Beyond Minimum) */
    public static function rotate(): void
    {
        unset($_SESSION[self::KEY]);
        self::token();
    }
}

/**
 * Validator — classe statica, regole componibili.
 * Pattern preso da Repo B (HRM-2) ed esteso.
 *
 * Uso:
 *   $v = Validator::check($_POST, [
 *       'email'    => ['required', 'email'],
 *       'age'      => ['int', 'min:18', 'max:120'],
 *       'username' => ['required', 'string:3,30', 'regex:/^[a-z0-9_]+$/i'],
 *   ]);
 *   if ($v->fails()) { $errors = $v->errors(); }
 */
final class Validator
{
    private array $errors = [];

    public static function check(array $data, array $rules): self
    {
        $v = new self();
        foreach ($rules as $field => $fieldRules) {
            $value = $data[$field] ?? null;
            foreach ($fieldRules as $rule) {
                $v->apply($field, $value, $rule);
            }
        }
        return $v;
    }

    public function fails(): bool  { return !empty($this->errors); }
    public function errors(): array { return $this->errors; }

    private function apply(string $field, $value, string $rule): void
    {
        [$name, $arg] = array_pad(explode(':', $rule, 2), 2, null);

        switch ($name) {
            case 'required':
                if ($value === null || $value === '' || (is_array($value) && !$value)) {
                    $this->errors[$field][] = "$field è obbligatorio";
                }
                break;
            case 'email':
                if ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $this->errors[$field][] = "$field non è un'email valida";
                }
                break;
            case 'int':
                if ($value !== null && $value !== '' && filter_var($value, FILTER_VALIDATE_INT) === false) {
                    $this->errors[$field][] = "$field deve essere un intero";
                }
                break;
            case 'min':
                if ($value !== null && is_numeric($value) && $value < (float)$arg) {
                    $this->errors[$field][] = "$field deve essere >= $arg";
                }
                break;
            case 'max':
                if ($value !== null && is_numeric($value) && $value > (float)$arg) {
                    $this->errors[$field][] = "$field deve essere <= $arg";
                }
                break;
            case 'string':
                [$lo, $hi] = array_pad(explode(',', (string)$arg), 2, null);
                $len = is_string($value) ? mb_strlen($value) : 0;
                if ($lo !== null && $len < (int)$lo) {
                    $this->errors[$field][] = "$field troppo corto (min $lo)";
                }
                if ($hi !== null && $len > (int)$hi) {
                    $this->errors[$field][] = "$field troppo lungo (max $hi)";
                }
                break;
            case 'regex':
                if ($value !== null && $value !== '' && !preg_match($arg, (string)$value)) {
                    $this->errors[$field][] = "$field formato non valido";
                }
                break;
            case 'in':
                $allowed = explode(',', (string)$arg);
                if ($value !== null && !in_array((string)$value, $allowed, true)) {
                    $this->errors[$field][] = "$field valore non consentito";
                }
                break;
            case 'url':
                if ($value !== null && $value !== '' && !filter_var($value, FILTER_VALIDATE_URL)) {
                    $this->errors[$field][] = "$field non è un URL valido";
                }
                break;
            case 'date':
                if ($value !== null && $value !== '') {
                    $d = DateTime::createFromFormat('Y-m-d', (string)$value);
                    if (!$d || $d->format('Y-m-d') !== $value) {
                        $this->errors[$field][] = "$field non è una data valida (Y-m-d)";
                    }
                }
                break;
        }
    }
}
