<?php
defined('SECURE_ACCESS') or die('Direct access not allowed');

/**
 * JWT HS256 encoder/decoder with JTI blacklist support.
 * No external library; manual implementation per RFC 7519.
 * See docs/AUTH_MODULE.md for full description.
 */
final class Jwt
{
    public static function encode(array $payload, int $expiry = JWT_ACCESS_EXPIRY): string
    {
        $now = time();
        $payload['iss'] = JWT_ISSUER;
        $payload['iat'] = $now;
        $payload['nbf'] = $now;
        $payload['exp'] = $now + $expiry;
        if (!isset($payload['jti'])) {
            $payload['jti'] = self::generateJti();
        }

        $header = ['typ' => 'JWT', 'alg' => 'HS256'];
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
        $parts = explode('.', $token);
        if (count($parts) !== 3) return null;
        [$h64, $p64, $s64] = $parts;

        $header = json_decode(self::base64UrlDecode($h64), true);
        $payload = json_decode(self::base64UrlDecode($p64), true);
        $sig = self::base64UrlDecode($s64);

        if (!is_array($header) || !is_array($payload) || $sig === false) return null;
        if (($header['alg'] ?? '') !== 'HS256') return null;

        $expected = hash_hmac('sha256', $h64 . '.' . $p64, self::secret(), true);
        if (!hash_equals($expected, $sig)) return null;

        $now = time();
        if (isset($payload['nbf']) && $now < (int)$payload['nbf']) return null;
        if (isset($payload['exp']) && $now >= (int)$payload['exp']) return null;
        if (isset($payload['iss']) && $payload['iss'] !== JWT_ISSUER) return null;
        if (!empty($payload['jti']) && self::isBlacklisted($payload['jti'])) return null;

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
        $cfg = Config::get('jwt');
        $secret = $cfg['secret_key'] ?? '';
        if (strlen($secret) < 32) {
            throw new RuntimeException('JWT secret_key not configured (min 32 chars).');
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
