<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * /api/auth/login    POST {email, password, totp?}
 * /api/auth/refresh  POST {refresh_token}
 * /api/auth/logout   POST  (Bearer)
 * /api/auth/me       GET   (Bearer)
 *
 * Rate-limit policy:
 *   login : 10 req / 5 min / IP   (bucket 'api_login')
 */
final class AuthController extends BaseController
{
    private const LOGIN_MAX    = 10;
    private const LOGIN_WINDOW = 300; // 5 minuti

    public function login(): void
    {
        $this->requireMethod('POST');
        $key = $this->throttleByIp('api_login', self::LOGIN_MAX, self::LOGIN_WINDOW, 'API login rate-limited');

        $in    = $this->getJsonInput();
        $email = trim((string)($in['email'] ?? ''));
        $pass  = (string)($in['password'] ?? '');
        $totp  = isset($in['totp']) ? (string)$in['totp'] : null;

        if (!Validator::email($email) || $pass === '') {
            $this->json(['error' => 'invalid_input'], 400);
        }

        $user = UserModel::verifyCredentials($email, $pass);
        if (!$user) {
            Logger::security('API login failed', [
                'gdpr_sensitive' => 1, 'email' => $email,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
            ]);
            $this->json(['error' => 'invalid_credentials'], 401);
        }

        if (!empty($user['totp_enabled'])) {
            if ($totp === null || $totp === '') {
                $this->json(['error' => 'totp_required'], 401);
            }
            $secret = UserModel::getTotpSecret((int)$user['id']);
            if (!$secret || !Totp::verify($secret, $totp)) {
                Logger::security('API TOTP failed', ['gdpr_sensitive' => 1, 'user_id' => (int)$user['id']]);
                $this->json(['error' => 'invalid_totp'], 401);
            }
        }

        // login OK -> azzera il counter di brute-force per questo IP
        RateLimiter::reset($key);

        $this->json($this->issueTokenPair((int)$user['id'], $user['email']));
    }

    public function refresh(): void
    {
        $this->requireMethod('POST');

        $in    = $this->getJsonInput();
        $token = (string)($in['refresh_token'] ?? '');
        if ($token === '') $this->json(['error' => 'missing_refresh_token'], 400);

        $payload = Jwt::decode($token);
        if (!$payload || ($payload['typ'] ?? '') !== 'refresh' || empty($payload['user_id']) || empty($payload['jti'])) {
            $this->json(['error' => 'invalid_refresh_token'], 401);
        }
        $userId = (int)$payload['user_id'];
        $oldJti = (string)$payload['jti'];

        $user = UserModel::findByIdInternal($userId);
        if (!$user) $this->json(['error' => 'user_not_found'], 401);

        $newJti = Jwt::generateJti();
        $newExp = time() + JWT_REFRESH_EXPIRY;
        if (!RefreshTokenModel::rotate($userId, $oldJti, $newJti, $newExp)) {
            Logger::security('Refresh-token reuse or revoked', ['user_id' => $userId]);
            RefreshTokenModel::revokeAllForUser($userId);
            $this->json(['error' => 'token_revoked'], 401);
        }

        $this->json([
            'access_token'  => Jwt::encode(['user_id' => $userId, 'email' => $user['email'], 'typ' => 'access'], JWT_ACCESS_EXPIRY),
            'refresh_token' => Jwt::encode(['user_id' => $userId, 'typ' => 'refresh', 'jti' => $newJti], JWT_REFRESH_EXPIRY),
            'token_type'    => 'Bearer',
            'expires_in'    => JWT_ACCESS_EXPIRY,
        ]);
    }

    public function logout(): void
    {
        $this->requireMethod('POST');
        $payload = $this->requireJwt();
        if (!empty($payload['jti']) && !empty($payload['exp'])) {
            Jwt::blacklist((string)$payload['jti'], (int)$payload['exp']);
        }
        RefreshTokenModel::revokeAllForUser((int)$payload['user_id']);
        Logger::security('API logout', ['user_id' => (int)$payload['user_id']]);
        $this->json(['ok' => true]);
    }

    public function me(): void
    {
        $this->requireMethod('GET');
        $payload = $this->requireJwt();
        $user = UserModel::findByIdInternal((int)$payload['user_id']);
        if (!$user) $this->json(['error' => 'user_not_found'], 404);
        $this->json(['user' => $user]);
    }
}
