<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * app/Controllers/HomeController.php
 * --------------------------------------------------------------------
 * Esempio di pagina pubblica (no auth richiesta).
 * --------------------------------------------------------------------
 */
final class HomeController extends BaseController
{
    public function index(): void
    {
        $this->view('home', [
            'title'   => 'Benvenuto',
            'message' => 'Template base caricato correttamente.',
        ]);
    }

    public function about(): void
    {
        $this->view('home', [
            'title'   => 'Chi siamo',
            'message' => 'Micro-framework PHP sicuro per hosting condiviso.',
        ]);
    }
}
