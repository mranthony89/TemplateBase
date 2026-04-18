<?php
/**
 * public_html/index.php
 * --------------------------------------------------------------------
 * FRONT CONTROLLER — unico punto di ingresso HTTP dell'applicazione.
 * Tutte le URL sono riscritte qui da public_html/.htaccess.
 * --------------------------------------------------------------------
 */

// Bootstrap: definisce SECURE_ACCESS, costanti, autoloader, sessione
require_once dirname(__DIR__) . '/system/bootstrap.php';

// Dispatch
Router::dispatch();
