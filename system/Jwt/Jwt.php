<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * JWT HS256 encoder/decoder con supporto JTI-blacklist.
 * Implementazione manuale RFC 7519 (zero deps).
 *
 * Decoding strict: tutti i claim obbligatori (exp, iat, iss, jti) DEVONO
 * essere presenti, altrimenti il token e' rifiutato. Questo previene il
 * bypass via 'token forgiato senza exp' in caso di leak della secret key:
 * il blacklist viene comunque controllato perche' jti e' richiesto.
 *
 * Il claim 'tv' (token_version) e 'typ' NON sono validati qui: sono
 * specifici dei flussi access-vs-refresh, e BaseController::requireJwt li
 * controlla per gli access token (multi-device revocation).
 */
final class Jwt
{
    private static function expectedAlg(): string
    {
        $alg = defined('JWT_ALGO') ? (string)JWT_ALGO : 'HS256';
        if ($alg !== 'HS256') {
            $msg = "JWT_ALGO='$alg' non supportato (solo HS256).";
            Logger::error($msg);
            throw new RuntimeException($msg);
        }
        return 'HS256';
    }

    public static function encode(array $payload, int $expiry = JWT_ACCESS_EXPIRY): string
    {
        $alg = self::expectedAlg();
        $now = time();
        $payload['iss'] = JWT_ISSUER;
        $payload['iat'] = $now;
        $payload['nbf'] = $now;
        $payload['exp'] = $now + $expiry;
        if (!isset($payload['jti'])) {
            $payload['jti'] = self::generateJti();
        }

        $header = ['typ' => 'JWT', 'alg' => $alg];
        $segments = [
            self::base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES)),
            self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES)),
        ];
        $signing = implode('.', $segments);
        $signature = hash_hmac('sha256', $signing, self::secret(), true);
        $segments[] = self::base64UrlEncode($signature);

        return implode('.', $segments);
    }

    public static function decode(string $token): ?array
    {
        $alg = self::expectedAlg();
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;
        [$h64, $p64, $s64] = $parts;

        $header  = json_decode(self::base64UrlDecode($h64), true);
        $payload = json_decode(self::base64UrlDecode($p64), true);
        $sig     = self::base64UrlDecode($s64);

        if (!is_array($header) || !is_array($payload) || $sig === false) return null;
        if (($header['alg'] ?? '') !== $alg) return null;
        if (($header['typ'] ?? '') !== 'JWT') return null;

        $expected = hash_hmac('sha256', $h64 . '.' . $p64, self::secret(), true);
        if (!hash_equals($expected, $sig)) return null;

        // Claim obbligatori (defense-in-depth contro forgery con claim mancanti).
        foreach (['exp', 'iat', 'iss', 'jti'] as $req) {
            if (!isset($payload[$req])) return null;
        }

        $now = time();
        if (isset($payload['nbf']) && $now < (int)$payload['nbf']) return null;
        if ($now >= (int)$payload['exp']) return null;
        if ($payload['iss'] !== JWT_ISSUER) return null;
        if (self::isBlacklisted((string)$payload['jti'])) return null;

        return $payload;
    }

    public static function blacklist(string $jti, int $exp): void
    {
        JwtBlacklistModel::add($jti, $exp);
    }

    public static function isBlacklisted(string $jti): bool
    {
        return JwtBlacklistModel::isBlacklisted($jti);
    }

    public static function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }

    private static function secret(): string
    {
        $secret = (string)Config::require('jwt.secret_key');
        if (strlen($secret) < 32) {
            $msg = 'JWT secret_key troppo corto: minimo 32 caratteri.';
            Logger::error($msg);
            throw new RuntimeException($msg);
        }
        return $secret;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/')) ?: '';
    }
}
