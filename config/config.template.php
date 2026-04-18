<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * config/config.template.php
 * --------------------------------------------------------------------
 * TEMPLATE — Copiare come config/config.php e compilare i valori.
 *
 *     cp config/config.template.php config/config.php
 *     chmod 600 config/config.php   # solo l'owner può leggere
 *
 * config.php NON deve MAI essere committato (aggiunto a .gitignore).
 * Questo file invece PUÒ essere committato: contiene solo placeholder.
 * --------------------------------------------------------------------
 */

return [
    'db' => [
        'host'    => 'localhost',
        'port'    => 3306,
        'name'    => 'CHANGE_ME_db_name',
        'user'    => 'CHANGE_ME_db_user',
        'pass'    => 'CHANGE_ME_strong_password',
        'charset' => 'utf8mb4',
    ],

    // Secret per signing (cookies firmati, token remember-me, ecc.)
    // Generare con: php -r "echo bin2hex(random_bytes(32));"
    'app_secret' => 'CHANGE_ME_64_hex_chars_random_bytes_32',

    // Email di sistema (mittente notifiche)
    'mail' => [
        'from_address' => 'no-reply@example.com',
        'from_name'    => 'Template Base',
    ],
];
