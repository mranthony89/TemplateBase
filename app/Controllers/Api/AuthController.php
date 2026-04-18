<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * /api/auth/login    POST {email, password, totp?}
 * /api/auth/refresh  POST {refresh_token}
 * /api/auth/logout   POST  (Bearer)
 * /api/auth/me       GET   (Bearer)
 */
final class AuthController extends BaseController
{
    public function login(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') $this->json(['error' => 'method_not_allowed'], 405);

        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $rl = new RateLimiter('api_login_' . hash('sha256', $ip), 10, 300);
        if (!$rl->throttle()) $this->json(['error' => 'rate_limited', 'retry_after' => $rl->reset()], 429);

        $in = $this->getJsonInput();
        $email = trim((string)($in['email'] ?? ''));
        $pass  = (string)($in['password'] ?? '');
        $totp  = isset($in['totp']) ? (string)$in['totp'] : null;

        if (!Validator::email($email) || $pass === '') $this->json(['error' => 'invalid_input'], 400);

        $user = UserModel::verifyCredentials($email, $pass);
        if (!$user) {
            Logger::security('API login failed', ['gdpr_sensitive' => 1, 'email' => $email, 'ip' => $ip]);
            $this->json(['error' => 'invalid_credentials'], 401);
        }

        if (!empty($user['totp_enabled'])) {
            if ($totp === null || $totp === '') $this->json(['error' => 'totp_required'], 401);
            $secret = UserModel::getTotpSecret((int)$user['id']);
            if (!$secret || !Totp::verify($secret, $totp)) {
                Logger::security('API TOTP failed', ['gdpr_sensitive' => 1, 'user_id' => (int)$user['id']]);
                $this->json(['error' => 'invalid_totp'], 401);
            }
        }

        $this->issueTokens((int)$user['id'], $user['email']);
    }

    public function refresh(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') $this->json(['error' => 'method_not_allowed'], 405);

        $in = $this->getJsonInput();
        $token = (string)($in['refresh_token'] ?? '');
        if ($token === '') $this->json(['error' => 'missing_refresh_token'], 400);

        $payload = Jwt::decode($token);
        if (!$payload || ($payload['typ'] ?? '') !== 'refresh' || empty($payload['user_id']) || empty($payload['jti'])) {
            $this->json(['error' => 'invalid_refresh_token'], 401);
        }
        $userId = (int)$payload['user_id'];
        $oldJti = (string)$payload['jti'];

        if (!RefreshTokenModel::isValid($userId, $oldJti)) {
            Logger::security('Refresh-token reuse or revoked', ['user_id' => $userId]);
            RefreshTokenModel::revokeAllForUser($userId);
            $this->json(['error' => 'token_revoked'], 401);
        }

        $user = UserModel::findByIdInternal($userId);
        if (!$user) $this->json(['error' => 'user_not_found'], 401);

        $newRefreshJti = Jwt::generateJti();
        $newRefreshExp = time() + JWT_REFRESH_EXPIRY;
        RefreshTokenModel::rotate($userId, $oldJti, $newRefreshJti, $newRefreshExp);

        $access  = Jwt::encode(['user_id' => $userId, 'email' => $user['email'], 'typ' => 'access'], JWT_ACCESS_EXPIRY);
        $refresh = Jwt::encode(['user_id' => $userId, 'typ' => 'refresh', 'jti' => $newRefreshJti], JWT_REFRESH_EXPIRY);

        $this->json([
            'access_token'  => $access,
            'refresh_token' => $refresh,
            'token_type'    => 'Bearer',
            'expires_in'    => JWT_ACCESS_EXPIRY,
        ]);
    }

    public function logout(): void
    {
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
        $payload = $this->requireJwt();
        $user = UserModel::findByIdInternal((int)$payload['user_id']);
        if (!$user) $this->json(['error' => 'user_not_found'], 404);
        $this->json(['user' => $user]);
    }

    private function issueTokens(int $userId, string $email): void
    {
        $refreshJti = Jwt::generateJti();
        $refreshExp = time() + JWT_REFRESH_EXPIRY;
        RefreshTokenModel::issue($userId, $refreshJti, $refreshExp);

        $access  = Jwt::encode(['user_id' => $userId, 'email' => $email, 'typ' => 'access'], JWT_ACCESS_EXPIRY);
        $refresh = Jwt::encode(['user_id' => $userId, 'typ' => 'refresh', 'jti' => $refreshJti], JWT_REFRESH_EXPIRY);

        $this->json([
            'access_token'  => $access,
            'refresh_token' => $refresh,
            'token_type'    => 'Bearer',
            'expires_in'    => JWT_ACCESS_EXPIRY,
        ]);
    }
}
