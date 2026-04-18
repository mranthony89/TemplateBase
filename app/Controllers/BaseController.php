<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * BaseController
 * --------------------------------------------------------------------
 * Classe astratta per tutti i controller (HTML e API).
 *
 *   view()         -> render view PHP da /app/Views/
 *   redirect()     -> redirect sicuro (solo path relativi)
 *   json()         -> output JSON + exit
 *   jsonError()    -> output JSON di errore (in dev include file/line/trace)
 *   requireAuth()  -> guard sessione web
 *   requireCsrf()  -> guard CSRF su POST/PUT/DELETE
 *   getJsonInput() -> decode body JSON delle API
 *   requireJwt()   -> guard Bearer JWT (API)
 *
 * Nessuno dei metodi qui è routabile: Router li esclude via Reflection.
 * --------------------------------------------------------------------
 */
abstract class BaseController
{
    protected function view(string $name, array $data = []): void
    {
        if (!preg_match('/^[a-zA-Z0-9_\/-]+$/', $name)) {
            throw new InvalidArgumentException('Nome view non valido');
        }
        $file = APP_PATH . '/Views/' . $name . '.php';
        if (!is_file($file)) {
            throw new RuntimeException("View non trovata: $name");
        }
        extract($data, EXTR_SKIP);
        require $file;
    }

    protected function redirect(string $path): void
    {
        if (!preg_match('#^/[A-Za-z0-9_/\-\?=&%\.]*$#', $path)) {
            Logger::security('Redirect rifiutato (URL non relativo)', ['path' => $path]);
            $path = '/';
        }
        header('Location: ' . $path);
        exit;
    }

    protected function json($data, int $status = 200): void
    {
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /**
     * Risposta di errore JSON. Usare al posto di json(['error'=>...], code)
     * quando l'errore nasce da un'eccezione: in development il body include
     * exception/message/file/line/trace per il debug immediato.
     */
    protected function jsonError(int $status, string $errorKey, ?\Throwable $e = null, array $extra = []): void
    {
        $body = ['error' => $errorKey];
        foreach ($extra as $k => $v) {
            if ($k !== 'error') $body[$k] = $v;
        }

        if ($e !== null) {
            Logger::error("API error [$errorKey]: " . $e->getMessage(), [
                'exception' => get_class($e),
                'file'      => $e->getFile(),
                'line'      => $e->getLine(),
                'status'    => $status,
            ]);
            if (defined('APP_ENV') && APP_ENV === 'development') {
                $body['exception'] = get_class($e);
                $body['message']   = $e->getMessage();
                $body['file']      = $e->getFile();
                $body['line']      = $e->getLine();
                $body['trace']     = explode("\n", $e->getTraceAsString());
            }
        }

        $this->json($body, $status);
    }

    protected function requireAuth(): int
    {
        $uid = $_SESSION['user_id'] ?? null;
        if (!$uid) {
            $this->redirect('/login');
        }
        return (int)$uid;
    }

    protected function requireCsrf(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'], true) && !CSRF::verify()) {
            http_response_code(403);
            die('CSRF token non valido');
        }
    }

    /** Decode del body JSON (POST /api/*). Array vuoto se parse fallisce. */
    protected function getJsonInput(): array
    {
        $raw = file_get_contents('php://input') ?: '';
        if ($raw === '') return [];
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            Logger::debug('getJsonInput: body non-JSON', ['len' => strlen($raw)]);
            return [];
        }
        return $data;
    }

    /**
     * Verifica il Bearer JWT in Authorization header.
     * In caso di successo ritorna il payload decodificato.
     * In caso di fallimento invia 401 JSON e termina.
     */
    protected function requireJwt(): array
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!$auth && function_exists('apache_request_headers')) {
            $h = apache_request_headers();
            $auth = $h['Authorization'] ?? $h['authorization'] ?? '';
        }
        if (stripos((string)$auth, 'Bearer ') !== 0) {
            $this->json(['error' => 'missing_token'], 401);
        }
        $token   = trim(substr((string)$auth, 7));
        $payload = Jwt::decode($token);
        if (!$payload || empty($payload['user_id'])) {
            Logger::security('JWT validation failed', [
                'gdpr_sensitive' => 1,
                'ip'             => $_SERVER['REMOTE_ADDR'] ?? '',
            ]);
            $this->json(['error' => 'invalid_token'], 401);
        }
        return $payload;
    }
}
