<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * /api/magic/request POST {email}
 * /api/magic/verify  POST {token}  (or GET ?token=)
 *
 * Rate-limit policy (RateLimiter is fully static):
 *   request : 5 req / 10 min / IP   key = 'api_magic_req_' . sha256(ip)
 */
final class MagicLinkController extends BaseController
{
    public function request(): void
    {
        if (!MAGIC_LINK_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            $this->json(['error' => 'method_not_allowed'], 405);
        }

        $ip  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $key = 'api_magic_req_' . hash('sha256', $ip);
        if (!RateLimiter::throttle($key, 5, 600)) {
            Logger::security('Magic-link rate-limited', ['gdpr_sensitive' => 1, 'ip' => $ip]);
            $this->json(['error' => 'rate_limited'], 429);
        }

        $in    = $this->getJsonInput();
        $email = trim((string)($in['email'] ?? ''));
        if (!Validator::email($email)) $this->json(['error' => 'invalid_email'], 400);

        $user = UserModel::findByEmail($email);
        if ($user) {
            $token = bin2hex(random_bytes(32));
            $exp   = time() + MAGIC_LINK_EXPIRY;
            MagicLinkModel::create((int)$user['id'], $token, $exp, $ip);

            $base = rtrim((string)Config::get('app.base_url', ''), '/');
            $url  = $base . '/api/magic/verify?token=' . urlencode($token);
            $body = "Per accedere clicca sul link (valido " . (MAGIC_LINK_EXPIRY / 60) . " minuti):\n\n$url\n\nSe non hai richiesto tu, ignora questa email.";
            try {
                Mailer::send($email, 'Il tuo link di accesso', $body);
            } catch (\Throwable $e) {
                Logger::error('Magic-link mail failed: ' . $e->getMessage(), [
                    'file' => $e->getFile(),
                    'line' => $e->getLine(),
                ]);
                if (defined('APP_ENV') && APP_ENV === 'development') {
                    throw $e; // loud in dev
                }
            }
        } else {
            Logger::security('Magic-link requested for unknown email', ['gdpr_sensitive' => 1, 'email' => $email]);
        }

        // Risposta uniforme per non rivelare se l'utente esiste
        $this->json(['ok' => true, 'message' => 'Se l\'email esiste, ti abbiamo inviato un link.']);
    }

    public function verify(): void
    {
        if (!MAGIC_LINK_ENABLED) $this->json(['error' => 'feature_disabled'], 404);

        $token = '';
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

        $refreshJti = Jwt::generateJti();
        $refreshExp = time() + JWT_REFRESH_EXPIRY;
        RefreshTokenModel::issue($userId, $refreshJti, $refreshExp);

        $access  = Jwt::encode(['user_id' => $userId, 'email' => $user['email'], 'typ' => 'access'], JWT_ACCESS_EXPIRY);
        $refresh = Jwt::encode(['user_id' => $userId, 'typ' => 'refresh', 'jti' => $refreshJti], JWT_REFRESH_EXPIRY);

        Logger::security('Magic-link consumed', ['user_id' => $userId]);

        $this->json([
            'access_token'  => $access,
            'refresh_token' => $refresh,
            'token_type'    => 'Bearer',
            'expires_in'    => JWT_ACCESS_EXPIRY,
        ]);
    }
}
