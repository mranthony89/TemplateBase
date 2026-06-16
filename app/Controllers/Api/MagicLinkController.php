<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * /api/magic/request POST {email}
 * /api/magic/verify  POST {token}  (oppure GET ?token=)
 *
 * Rate-limit policy:
 *   request : 5 req / 10 min / IP   (bucket 'api_magic_req')
 */
final class MagicLinkController extends BaseController
{
    private const REQ_MAX    = 5;
    private const REQ_WINDOW = 600; // 10 minuti

    public function request(): void
    {
        if (!MAGIC_LINK_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        $this->requireMethod('POST');
        $this->throttleByIp('api_magic_req', self::REQ_MAX, self::REQ_WINDOW, 'Magic-link rate-limited');

        $in    = $this->getJsonInput();
        $email = trim((string)($in['email'] ?? ''));
        if (!Validator::email($email)) $this->json(['error' => 'invalid_email'], 400);

        $user = UserModel::findByEmail($email);
        if ($user) {
            $token = bin2hex(random_bytes(32));
            $exp   = time() + MAGIC_LINK_EXPIRY;
            $ip    = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
            MagicLinkModel::create((int)$user['id'], $token, $exp, $ip);

            $base = rtrim((string)Config::get('app.base_url', ''), '/');
            $url  = $base . '/api/magic/verify?token=' . urlencode($token);
            $body = "Per accedere clicca sul link (valido " . (MAGIC_LINK_EXPIRY / 60) . " minuti):\n\n$url\n\nSe non hai richiesto tu, ignora questa email.";
            // Mailer::send gestisce gia' la policy loud-debug: rilancia in dev,
            // logga + ritorna false in prod. Non servono altri wrapper.
            Mailer::send($email, 'Il tuo link di accesso', $body);
        } else {
            Logger::security('Magic-link requested for unknown email', ['gdpr_sensitive' => 1, 'email' => $email]);
        }

        // Risposta uniforme: non rivelare se l'utente esiste.
        $this->json(['ok' => true, 'message' => 'Se l\'email esiste, ti abbiamo inviato un link.']);
    }

    public function verify(): void
    {
        if (!MAGIC_LINK_ENABLED) $this->json(['error' => 'feature_disabled'], 404);

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
            $in = $this->getJsonInput();
            $token = (string)($in['token'] ?? '');
        } else {
            $token = (string)($_GET['token'] ?? '');
        }
        if ($token === '' || !ctype_xdigit($token)) {
            $this->json(['error' => 'invalid_token'], 400);
        }

        $userId = MagicLinkModel::consume($token);
        if (!$userId) $this->json(['error' => 'invalid_or_used'], 401);

        $user = UserModel::findByIdInternal($userId);
        if (!$user) $this->json(['error' => 'user_not_found'], 404);

        Logger::security('Magic-link consumed', ['user_id' => $userId]);
        $this->json($this->issueTokenPair($userId, $user['email']));
    }
}
