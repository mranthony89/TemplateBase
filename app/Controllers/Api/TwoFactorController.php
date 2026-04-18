<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * /api/2fa/setup   POST  -> returns secret + provisioning URI (Bearer)
 * /api/2fa/enable  POST {code} (Bearer)
 * /api/2fa/disable POST {code} (Bearer)
 * /api/2fa/status  GET   (Bearer)
 */
final class TwoFactorController extends BaseController
{
    public function setup(): void
    {
        if (!TOTP_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        $payload = $this->requireJwt();
        $userId = (int)$payload['user_id'];

        $user = UserModel::findByIdInternal($userId);
        if (!$user) $this->json(['error' => 'user_not_found'], 404);

        if (UserModel::hasTotp($userId)) $this->json(['error' => 'totp_already_enabled'], 409);

        $secret = Totp::generateSecret();
        UserModel::setTotpSecret($userId, $secret);

        $uri = Totp::provisioningUri($secret, $user['email']);
        Logger::security('TOTP setup initiated', ['user_id' => $userId]);

        $this->json([
            'secret'             => $secret,
            'provisioning_uri'   => $uri,
            'digits'             => TOTP_DIGITS,
            'period'             => TOTP_PERIOD,
        ]);
    }

    public function enable(): void
    {
        if (!TOTP_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        $payload = $this->requireJwt();
        $userId = (int)$payload['user_id'];

        $in = $this->getJsonInput();
        $code = (string)($in['code'] ?? '');
        if ($code === '') $this->json(['error' => 'missing_code'], 400);

        $secret = UserModel::getTotpSecret($userId);
        if (!$secret) $this->json(['error' => 'no_pending_setup'], 400);

        if (!Totp::verify($secret, $code)) {
            Logger::security('TOTP enable failed', ['user_id' => $userId]);
            $this->json(['error' => 'invalid_code'], 401);
        }

        UserModel::enableTotp($userId);
        Logger::security('TOTP enabled', ['user_id' => $userId]);
        $this->json(['ok' => true]);
    }

    public function disable(): void
    {
        if (!TOTP_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        $payload = $this->requireJwt();
        $userId = (int)$payload['user_id'];

        $in = $this->getJsonInput();
        $code = (string)($in['code'] ?? '');
        if ($code === '') $this->json(['error' => 'missing_code'], 400);

        $secret = UserModel::getTotpSecret($userId);
        if (!$secret || !Totp::verify($secret, $code)) {
            Logger::security('TOTP disable failed', ['user_id' => $userId]);
            $this->json(['error' => 'invalid_code'], 401);
        }

        UserModel::disableTotp($userId);
        Logger::security('TOTP disabled', ['user_id' => $userId]);
        $this->json(['ok' => true]);
    }

    public function status(): void
    {
        if (!TOTP_ENABLED) $this->json(['error' => 'feature_disabled'], 404);
        $payload = $this->requireJwt();
        $userId = (int)$payload['user_id'];
        $this->json(['enabled' => UserModel::hasTotp($userId)]);
    }
}
