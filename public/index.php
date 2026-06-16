<?php
/**
 * public/index.php - Front Controller.
 * --------------------------------------------------------------------
 * Tutto il traffico HTTP transita da qui. Il try/catch globale e' la
 * safety-net che:
 *   - logga ogni Throwable non gestito con Logger::error(),
 *   - restituisce JSON se la richiesta e' API (/api/*), altrimenti HTML,
 *   - in development espone exception/message/file/line/trace nella
 *     risposta (loud-debug). In production mostra solo messaggio generico.
 * --------------------------------------------------------------------
 */
require_once dirname(__DIR__) . '/system/bootstrap.php';

try {
    Router::dispatch();
} catch (\Throwable $e) {
    Logger::error(
        'Unhandled exception in front-controller: ' . $e->getMessage(),
        Logger::throwableContext($e, true) + [
            'uri'    => $_SERVER['REQUEST_URI']    ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        ]
    );

    $isApi = isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/api/') !== false;
    $isDev = Env::isDev();

    if (!headers_sent()) {
        http_response_code(500);
    }

    if ($isApi) {
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
            header('X-Content-Type-Options: nosniff');
        }
        $body = ['error' => 'internal_error'];
        if ($isDev) {
            $body += Logger::throwableDevBody($e);
        }
        echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } else {
        if ($isDev) {
            echo '<!doctype html><meta charset="utf-8"><title>500</title>';
            echo '<h1>Unhandled exception</h1>';
            echo '<p><strong>' . htmlspecialchars(get_class($e), ENT_QUOTES, 'UTF-8') . ':</strong> '
                 . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</p>';
            echo '<p>' . htmlspecialchars($e->getFile(), ENT_QUOTES, 'UTF-8') . ':' . (int)$e->getLine() . '</p>';
            echo '<pre>' . htmlspecialchars($e->getTraceAsString(), ENT_QUOTES, 'UTF-8') . '</pre>';
        } else {
            echo '<!doctype html><meta charset="utf-8"><title>500</title>';
            echo '<h1>500 - Errore interno del server</h1>';
        }
    }
}
