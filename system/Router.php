<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * system/Router.php
 * --------------------------------------------------------------------
 * Router convention-based minimale.
 *
 * URL               → Controller             → Metodo
 * /                 → HomeController         → index
 * /home             → HomeController         → index
 * /home/about       → HomeController         → about
 * /dashboard        → DashboardController    → index
 * /dashboard/edit/42 → DashboardController   → edit  (arg: 42)
 *
 * Il nome di controller è sempre case-safe: ucfirst(lower(segment)) + 'Controller'.
 * I segmenti sono validati con regex per impedire iniezione nel filesystem.
 * --------------------------------------------------------------------
 */
final class Router
{
    public static function dispatch(): void
    {
        // Path richiesto — rimuovi query string
        $uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
        $uri = trim($uri, '/');

        // Default: home
        if ($uri === '' || $uri === 'index.php') {
            $uri = 'home';
        }

        $segments = explode('/', $uri);

        // Valida OGNI segmento: solo [a-zA-Z0-9_-], no path traversal, no null byte
        foreach ($segments as $s) {
            if (!preg_match('/^[a-zA-Z0-9_-]+$/', $s)) {
                self::notFound('Invalid route segment');
                return;
            }
        }

        $controllerName = ucfirst(strtolower($segments[0])) . 'Controller';
        $action         = isset($segments[1]) ? strtolower($segments[1]) : 'index';
        $args           = array_slice($segments, 2);

        $file = APP_PATH . '/Controllers/' . $controllerName . '.php';
        if (!is_file($file)) {
            self::notFound("Controller $controllerName not found");
            return;
        }
        require_once $file;

        if (!class_exists($controllerName)) {
            self::notFound("Class $controllerName missing in file");
            return;
        }

        $instance = new $controllerName();

        // Whitelist: solo metodi pubblici non ereditati da BaseController
        // (evita che /home/render invochi metodi interni del framework)
        if (!method_exists($instance, $action)) {
            self::notFound("Action $action not found in $controllerName");
            return;
        }
        $ref = new ReflectionMethod($instance, $action);
        if (!$ref->isPublic() || $ref->getDeclaringClass()->getName() === 'BaseController') {
            self::notFound("Action $action not routable");
            return;
        }

        // Invoca con gli argomenti rimanenti come parametri stringa
        call_user_func_array([$instance, $action], $args);
    }

    private static function notFound(string $reason = ''): void
    {
        Logger::debug('Router 404: ' . $reason, ['uri' => $_SERVER['REQUEST_URI'] ?? '']);
        http_response_code(404);
        echo '404 — Pagina non trovata';
    }
}
