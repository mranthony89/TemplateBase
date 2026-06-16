<?php
return [
    'db' => [
        'host'    => 'localhost',
        'port'    => 3306,
        'name'    => '',
        'user'    => '',
        'pass'    => '',
        'charset' => 'utf8mb4',
    ],
    'app_secret' => '', // bin2hex(random_bytes(32))
    'app' => [
        'base_url' => '', // es. https://app.example.com
    ],
    'auth' => [
        // HMAC server pepper. Usato da:
        //   - Logger          (hash email/IP nei log)
        //   - MagicLinkModel  (hash IP del richiedente)
        //   - BaseController  (bucket key del RateLimiter)
        // Generato con: php -r "echo bin2hex(random_bytes(32));"
        // ATTENZIONE: ruotarlo invalida tutti gli hash storati (rate-limit
        // counter / magic-link ip_hash). Usalo come pseudonymization secret
        // permanente, non come rotating secret.
        'pepper' => '',
    ],
    'jwt' => [
        'secret_key' => '', // bin2hex(random_bytes(32)) >= 32 byte
    ],
    'magic_link' => [
        'secret_key' => '', // bin2hex(random_bytes(32))
    ],
    'mail' => [
        'from' => [
            'address' => 'noreply@example.com',
            'name'    => APP_NAME,
        ],
        'smtp' => [
            'host'       => '',
            'port'       => 587,
            'username'   => '',
            'password'   => '',
            'encryption' => 'tls', // 'tls' | 'ssl' | ''
        ],
    ],
];
