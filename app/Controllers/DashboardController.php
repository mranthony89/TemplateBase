<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * app/Controllers/DashboardController.php
 * --------------------------------------------------------------------
 * Esempio di pagina PROTETTA con Zero Trust:
 *   - requireAuth() → verifica che l'utente sia loggato
 *   - Tutte le query al model passano $userId esplicito (Row-Level Security)
 * --------------------------------------------------------------------
 */
final class DashboardController extends BaseController
{
    public function index(): void
    {
        $userId = $this->requireAuth();

        // Zero Trust: chiedo SEMPRE solo ciò che appartiene all'utente corrente
        $user = UserModel::findByIdForUser($userId, $userId);

        if (!$user) {
            // Non dovrebbe mai accadere se la sessione è valida, ma difesa in profondità
            Logger::security('Auth utente senza record DB', ['user_id' => $userId]);
            session_destroy();
            $this->redirect('/login');
            return;
        }

        $this->view('home', [
            'title'   => 'Dashboard',
            'message' => 'Ciao ' . $user['email'] . ', questa è la tua area privata.',
        ]);
    }

    public function update(): void
    {
        $userId = $this->requireAuth();
        $this->requireCsrf(); // obbligatorio su POST

        $v = Validator::check($_POST, [
            'email' => ['required', 'email', 'string:3,255'],
        ]);
        if ($v->fails()) {
            $this->json(['ok' => false, 'errors' => $v->errors()], 422);
            return;
        }

        // RLS: l'UPDATE ha SEMPRE WHERE id = ? (l'id dell'utente loggato)
        UserModel::updateEmail($userId, $_POST['email']);
        CSRF::rotate(); // rotazione post-azione sensibile (Beyond Minimum)

        $this->json(['ok' => true]);
    }
}
