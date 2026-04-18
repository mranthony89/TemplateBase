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
    'jwt' => [
        'secret_key' => '', // bin2hex(random_bytes(32)) >= 32 byte
    ],
    'magic_link' => [
        'secret_key' => '', // bin2hex(random_bytes(32))
        'base_url'   => '', // es. https://app.example.com
    ],
    'mail' => [
        'from_address' => 'noreply@example.com',
        'from_name'    => APP_NAME,
        'smtp' => [
            'host'       => '',
            'port'       => 587,
            'username'   => '',
            'password'   => '',
            'encryption' => 'tls', // 'tls' | 'ssl' | ''
        ],
    ],
];
