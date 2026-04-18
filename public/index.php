<?php
/**
 * public/index.php — Front Controller.
 * --------------------------------------------------------------------
 * Tutto il traffico HTTP transita da qui. Il try/catch globale è la
 * safety-net che:
 *   - logga ogni Throwable non gestito con Logger::error(),
 *   - restituisce JSON se la richiesta è API (/api/*), altrimenti HTML,
 *   - in development espone file/line/trace nella risposta
 *     (loud-debug). In production mostra solo un messaggio generico.
 * --------------------------------------------------------------------
 */
require_once dirname(__DIR__) . '/system/bootstrap.php';

try {
    Router::dispatch();
} catch (\Throwable $e) {
    // Log strutturato (il set_error_handler/set_exception_handler in
    // bootstrap.php loggano comunque; qui replichiamo in modo esplicito
    // per associare il contesto alla richiesta corrente).
    Logger::error('Unhandled exception in front-controller: ' . $e->getMessage(), [
        'exception' => get_class($e),
        'file'      => $e->getFile(),
        'line'      => $e->getLine(),
        'uri'       => $_SERVER['REQUEST_URI']   ?? '',
        'method'    => $_SERVER['REQUEST_METHOD'] ?? '',
        'trace'     => $e->getTraceAsString(),
    ]);

    $isApi = isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/api/') !== false;
    $isDev = defined('APP_ENV') && APP_ENV === 'development';

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
            $body['exception'] = get_class($e);
            $body['message']   = $e->getMessage();
            $body['file']      = $e->getFile();
            $body['line']      = $e->getLine();
            $body['trace']     = explode("\n", $e->getTraceAsString());
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
            echo '<h1>500 — Errore interno del server</h1>';
        }
    }
}
