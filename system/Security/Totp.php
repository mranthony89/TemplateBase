<?php
defined('SECURE_ACCESS') or die('Direct access not allowed');

/**
 * RFC 6238 TOTP implementation (Google Authenticator compatible).
 * No external dependency. See docs/AUTH_MODULE.md.
 */
final class Totp
{
    public static function generateSecret(int $length = 20): string
    {
        return self::base32Encode(random_bytes($length));
    }

    public static function verify(string $secret, string $code, int $window = 1): bool
    {
        $code = preg_replace('/\s+/', '', $code);
        if (!ctype_digit($code) || strlen($code) !== TOTP_DIGITS) {
            return false;
        }
        $timeSlice = (int)floor(time() / TOTP_PERIOD);
        for ($i = -$window; $i <= $window; $i++) {
            $candidate = self::computeCode($secret, $timeSlice + $i);
            if (hash_equals($candidate, $code)) {
                return true;
            }
        }
        return false;
    }

    public static function provisioningUri(string $secret, string $accountName, ?string $issuer = null): string
    {
        $issuer = $issuer ?? TOTP_ISSUER;
        $label = rawurlencode($issuer . ':' . $accountName);
        $params = http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => strtoupper(TOTP_ALGO),
            'digits'    => TOTP_DIGITS,
            'period'    => TOTP_PERIOD,
        ]);
        return 'otpauth://totp/' . $label . '?' . $params;
    }

    private static function computeCode(string $secret, int $timeSlice): string
    {
        $key = self::base32Decode($secret);
        $bin = pack('N*', 0) . pack('N*', $timeSlice);
        $hash = hash_hmac(TOTP_ALGO, $bin, $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $part = substr($hash, $offset, 4);
        $value = unpack('N', $part)[1] & 0x7FFFFFFF;
        $code = $value % (10 ** TOTP_DIGITS);
        return str_pad((string)$code, TOTP_DIGITS, '0', STR_PAD_LEFT);
    }

    private static function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        foreach (str_split($data) as $c) {
            $binary .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $chunks = str_split($binary, 5);
        $out = '';
        foreach ($chunks as $chunk) {
            $chunk = str_pad($chunk, 5, '0');
            $out .= $alphabet[bindec($chunk)];
        }
        $pad = (8 - (strlen($out) % 8)) % 8;
        return $out . str_repeat('=', $pad);
    }

    private static function base32Decode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = rtrim(strtoupper($data), '=');
        $binary = '';
        foreach (str_split($data) as $c) {
            $pos = strpos($alphabet, $c);
            if ($pos === false) {
                continue;
            }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = '';
        foreach (str_split($binary, 8) as $byte) {
            if (strlen($byte) === 8) {
                $bytes .= chr(bindec($byte));
            }
        }
        return $bytes;
    }
}
