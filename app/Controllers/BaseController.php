<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * app/Controllers/BaseController.php
 * --------------------------------------------------------------------
 * Classe astratta comune: render view, redirect sicuro, check auth,
 * verifica CSRF per richieste POST.
 *
 * I metodi di questa classe NON sono routabili (il Router li esclude
 * via ReflectionMethod::getDeclaringClass check).
 * --------------------------------------------------------------------
 */
abstract class BaseController
{
    /**
     * Rende una view PHP passandole $data come variabili locali.
     * Le view stanno in /app/Views/ e DEVONO usare h() per l'output.
     */
    protected function view(string $name, array $data = []): void
    {
        // Valida il nome view (no path traversal)
        if (!preg_match('/^[a-zA-Z0-9_\/-]+$/', $name)) {
            throw new InvalidArgumentException('Nome view non valido');
        }
        $file = APP_PATH . '/Views/' . $name . '.php';
        if (!is_file($file)) {
            throw new RuntimeException("View non trovata: $name");
        }
        // extract con EXTR_SKIP: mai sovrascrivere variabili esistenti
        extract($data, EXTR_SKIP);
        require $file;
    }

    /**
     * Redirect sicuro: SOLO path relativi (inizianti con /).
     * Previene open redirect: un URL esterno viene rifiutato.
     */
    protected function redirect(string $path): void
    {
        if (!preg_match('#^/[A-Za-z0-9_/\-\?=&%\.]*$#', $path)) {
            Logger::security('Redirect rifiutato (URL non relativo)', ['path' => $path]);
            $path = '/';
        }
        header('Location: ' . $path);
        exit;
    }

    /** Risposta JSON (utile per endpoint AJAX) */
    protected function json($data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /** Richiede utente autenticato. Altrimenti redirect a /login. */
    protected function requireAuth(): int
    {
        $uid = $_SESSION['user_id'] ?? null;
        if (!$uid) {
            $this->redirect('/login');
        }
        return (int)$uid;
    }

    /**
     * Verifica CSRF obbligatoria per POST/PUT/DELETE.
     * Chiamare a inizio di ogni action che modifica stato.
     */
    protected function requireCsrf(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if (in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'], true) && !CSRF::verify()) {
            http_response_code(403);
            die('CSRF token non valido');
        }
    }
}
