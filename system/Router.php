<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * system/Router.php — convention-based.
 *
 * Web routes:
 *   /                 → HomeController::index
 *   /dashboard/edit/42 → DashboardController::edit(42)
 *
 * API routes:
 *   /api/auth/login   → Api\AuthController::login (file: app/Controllers/Api/AuthController.php)
 *   /api/2fa/setup    → Api\TwoFactorController::setup
 *
 * Tutti i segmenti sono validati: solo [a-zA-Z0-9_-].
 */
final class Router
{
    public static function dispatch(): void
    {
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
        $uri = trim($uri, '/');

        if ($uri === '' || $uri === 'index.php') {
            $uri = 'home';
        }

        $segments = explode('/', $uri);
        foreach ($segments as $s) {
            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $s)) {
                self::notFound('Invalid route segment');
                return;
            }
        }

        $isApi = ($segments[0] === 'api');
        if ($isApi) {
            self::dispatchApi(array_slice($segments, 1));
            return;
        }

        $controllerName = ucfirst(strtolower($segments[0])) . 'Controller';
        $action         = isset($segments[1]) ? strtolower($segments[1]) : 'index';
        $args           = array_slice($segments, 2);

        self::invoke(APP_PATH . '/Controllers/' . $controllerName . '.php', $controllerName, $action, $args);
    }

    private static function dispatchApi(array $segments): void
    {
        if (empty($segments)) {
            self::jsonError(404, 'API resource missing');
            return;
        }
        $resourceMap = [
            'auth'  => 'AuthController',
            'magic' => 'MagicLinkController',
            '2fa'   => 'TwoFactorController',
        ];
        $key = strtolower($segments[0]);
        if (!isset($resourceMap[$key])) {
            self::jsonError(404, 'API resource not found');
            return;
        }
        $controllerName = $resourceMap[$key];
        $action = isset($segments[1]) ? strtolower($segments[1]) : 'index';
        $args   = array_slice($segments, 2);

        self::invoke(
            APP_PATH . '/Controllers/Api/' . $controllerName . '.php',
            $controllerName,
            $action,
            $args,
            true
        );
    }

    private static function invoke(string $file, string $controllerName, string $action, array $args, bool $jsonMode = false): void
    {
        if (!is_file($file)) {
            $jsonMode ? self::jsonError(404, "Controller $controllerName not found")
                      : self::notFound("Controller $controllerName not found");
            return;
        }
        require_once $file;

        if (!class_exists($controllerName)) {
            $jsonMode ? self::jsonError(500, "Class $controllerName missing")
                      : self::notFound("Class $controllerName missing");
            return;
        }
        $instance = new $controllerName();

        if (!method_exists($instance, $action)) {
            $jsonMode ? self::jsonError(404, "Action $action not found")
                      : self::notFound("Action $action not found");
            return;
        }
        $ref = new ReflectionMethod($instance, $action);
        if (!$ref->isPublic() || $ref->getDeclaringClass()->getName() === 'BaseController') {
            $jsonMode ? self::jsonError(404, "Action $action not routable")
                      : self::notFound("Action $action not routable");
            return;
        }

        call_user_func_array([$instance, $action], $args);
    }

    private static function notFound(string $reason = ''): void
    {
        Logger::debug('Router 404: ' . $reason, ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
        http_response_code(404);
        echo '404 — Pagina non trovata';
    }

    private static function jsonError(int $code, string $reason = ''): void
    {
        Logger::debug('API ' . $code . ': ' . $reason, ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
        http_response_code($code);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['error' => $reason ?: 'API error']);
    }
}
