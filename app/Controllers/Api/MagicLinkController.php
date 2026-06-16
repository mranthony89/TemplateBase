<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * /api/magic/request POST {email}
 * /api/magic/verify  POST {token, totp?}  oppure GET ?token=...
 *
 * Rate-limit:
 *   request : 5  req / 10 min / IP   (bucket 'api_magic_req')
 *   verify  : 10 req / 15 min / IP   (bucket 'api_magic_verify')
 *
 * Security:
 *   - Il token e' validato come 64-hex-char (output di bin2hex(random_bytes(32))).
 *   - Se l'utente ha TOTP attivo, verify richiede anche il code TOTP nel body POST.
 *     Senza TOTP, magic-link sarebbe un bypass completo del 2FA.
 *   - verify accetta GET per compatibilita' con i client email che seguono il
 *     link direttamente. La GET non puo' trasportare il TOTP: utenti con 2FA
 *     attivo devono completare via POST.
 */
final class MagicLinkController extends BaseController
{
    private const REQ_MAX       = 5;
    private const REQ_WINDOW    = 600;  // 10 minuti
    private const VERIFY_MAX    = 10;
    private const VERIFY_WINDOW = 900;  // 15 minuti
    private const TOKEN_LEN     = 64;   // bin2hex(random_bytes(32))

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
            // Mailer::send gestisce gia' la policy loud-debug (rilancia in dev,
            // logga + ritorna false in prod): non servono altri wrapper.
            Mailer::send($email, 'Il tuo link di accesso', $body);
        } else {
            // Logger sanitizeContext hashera' l'email via HMAC (con pepper) o sha256.
            Logger::security('Magic-link requested for unknown email', ['gdpr_sensitive' => 1, 'email' => $email]);
        }

        // Risposta uniforme per non rivelare se l'utente esiste.
        $this->json(['ok' => true, 'message' => 'Se l\'email esiste, ti abbiamo inviato un link.']);
    }

    public function verify(): void
    {
        if (!MAGIC_LINK_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        // Rate-limit anche su verify: previene grinding e timing su token validi.
        $this->throttleByIp('api_magic_verify', self::VERIFY_MAX, self::VERIFY_WINDOW, 'Magic-link verify rate-limited');

        $isPost = (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST');
        if ($isPost) {
            $in    = $this->getJsonInput();
            $token = (string)($in['token'] ?? '');
            $totp  = isset($in['totp']) ? (string)$in['totp'] : null;
        } else {
            $token = (string)($_GET['token'] ?? '');
            $totp  = null;
        }

        if ($token === '' || strlen($token) !== self::TOKEN_LEN || !ctype_xdigit($token)) {
            $this->json(['error' => 'invalid_token'], 400);
        }

        $userId = MagicLinkModel::consume($token);
        if (!$userId) $this->json(['error' => 'invalid_or_used'], 401);

        $user = UserModel::findByIdInternal($userId);
        if (!$user) $this->json(['error' => 'user_not_found'], 404);

        // TOTP gate: magic-link da solo NON deve bypassare il 2FA dell'utente.
        if (!empty($user['totp_enabled'])) {
            if ($totp === null || $totp === '') {
                Logger::security('Magic-link verify TOTP required', ['user_id' => $userId]);
                $this->json(['error' => 'totp_required'], 401);
            }
            $secret = UserModel::getTotpSecret($userId);
            if (!$secret || !Totp::verify($secret, $totp)) {
                Logger::security('Magic-link verify TOTP failed', ['user_id' => $userId]);
                $this->json(['error' => 'invalid_totp'], 401);
            }
        }

        Logger::security('Magic-link consumed', ['user_id' => $userId]);
        $this->json($this->issueTokenPair($userId, $user['email']));
    }
}
