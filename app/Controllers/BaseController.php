<?php
if (!defined('SECURE_ACCESS')) die;

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
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
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

    /**
     * Decode JSON body of an API request. Returns array (empty on parse failure).
     */
    protected function getJsonInput(): array
    {
        $raw = file_get_contents('php://input') ?: '';
        if ($raw === '') return [];
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    /**
     * Validate a Bearer JWT in the Authorization header.
     * On success, returns the decoded payload (with user_id, jti, exp, ...).
     * On failure, sends 401 JSON and exits.
     */
    protected function requireJwt(): array
    {
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!$auth && function_exists('apache_request_headers')) {
            $h = apache_request_headers();
            $auth = $h['Authorization'] ?? $h['authorization'] ?? '';
        }
        if (stripos($auth, 'Bearer ') !== 0) {
            $this->json(['error' => 'missing_token'], 401);
        }
        $token = trim(substr($auth, 7));
        $payload = Jwt::decode($token);
        if (!$payload || empty($payload['user_id'])) {
            Logger::security('JWT validation failed', ['gdpr_sensitive' => 1, 'ip' => $_SERVER['REMOTE_ADDR'] ?? '']);
            $this->json(['error' => 'invalid_token'], 401);
        }
        return $payload;
    }
}
