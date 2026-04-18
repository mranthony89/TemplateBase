<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * Lazy wrapper for vendored PHPMailer.
 * Files expected in:  system/lib/PHPMailer/src/{Exception,PHPMailer,SMTP}.php
 * (download from https://github.com/PHPMailer/PHPMailer/releases — see INSTALL.md §5).
 *
 * Loud-debug policy:
 *   APP_ENV === 'development'  -> SMTPDebug=2, exception re-thrown after logging.
 *   APP_ENV === 'production'   -> error logged, returns false.
 */
final class Mailer
{
    private static bool $loaded = false;

    private static function load(): void
    {
        if (self::$loaded) return;

        $base  = SYSTEM_PATH . '/lib/PHPMailer/src';
        $files = ['Exception.php', 'PHPMailer.php', 'SMTP.php'];

        $missing = [];
        foreach ($files as $f) {
            $path = $base . '/' . $f;
            if (!is_file($path)) {
                $missing[] = $path;
                continue;
            }
            require_once $path;
        }
        if ($missing) {
            $msg = 'PHPMailer non installato. File mancanti: ' . implode(', ', $missing)
                 . '. Vedi INSTALL.md §5 ("PHPMailer") per il download.';
            Logger::error($msg);
            throw new RuntimeException($msg);
        }
        self::$loaded = true;
    }

    public static function send(string $to, string $subject, string $body, bool $html = true): bool
    {
        self::load();

        $cfg  = $GLOBALS['config']['mail']  ?? [];
        $smtp = $cfg['smtp']                ?? [];
        $from = $cfg['from']                ?? [];

        $isDev = defined('APP_ENV') && APP_ENV === 'development';

        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

        if ($isDev) {
            $mail->SMTPDebug   = 2; // verbose SMTP transcript
            $mail->Debugoutput = function ($str, $level) {
                Logger::debug('PHPMailer[' . $level . ']: ' . trim($str));
            };
        }

        try {
            if (!empty($smtp['host'])) {
                $mail->isSMTP();
                $mail->Host       = (string)$smtp['host'];
                $mail->Port       = (int)($smtp['port'] ?? 587);
                $mail->SMTPAuth   = !empty($smtp['username']);
                $mail->Username   = (string)($smtp['username'] ?? '');
                $mail->Password   = (string)($smtp['password'] ?? '');
                $enc = strtolower((string)($smtp['encryption'] ?? 'tls'));
                if ($enc === 'tls') $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                if ($enc === 'ssl') $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
                $mail->SMTPAutoTLS = true;
            } else {
                $mail->isMail();
            }

            $mail->CharSet  = 'UTF-8';
            $mail->Encoding = 'base64';
            $mail->setFrom(
                (string)($from['address'] ?? $cfg['from_address'] ?? 'noreply@localhost'),
                (string)($from['name']    ?? $cfg['from_name']    ?? (defined('APP_NAME') ? APP_NAME : 'App'))
            );
            $mail->addAddress($to);
            $mail->Subject = $subject;
            $mail->isHTML($html);
            $mail->Body = $body;
            if ($html) {
                $mail->AltBody = trim(strip_tags($body));
            }

            $ok = $mail->send();
            if ($ok) {
                Logger::debug('Mail inviata', ['to' => $to, 'subject' => $subject]);
            } else {
                Logger::error('Mail send returned false: ' . $mail->ErrorInfo, ['to' => $to]);
                if ($isDev) {
                    throw new RuntimeException('Mail send failed: ' . $mail->ErrorInfo);
                }
            }
            return $ok;
        } catch (\Throwable $e) {
            Logger::error('Mail send failed: ' . $e->getMessage(), [
                'to'    => $to,
                'file'  => $e->getFile(),
                'line'  => $e->getLine(),
            ]);
            if ($isDev) throw $e; // loud in dev
            return false;
        }
    }
}
