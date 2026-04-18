<?php
if (!defined('SECURE_ACCESS')) die;

// PHPMailer caricato lazy: se la cartella system/lib/PHPMailer/ non c'è,
// l'errore è gestito al primo invio (vedi INSTALL.md per il download).

final class Mailer
{
    private static bool $loaded = false;

    private static function load(): void
    {
        if (self::$loaded) return;
        $base = SYSTEM_PATH . '/lib/PHPMailer/src';
        $files = ['Exception.php', 'PHPMailer.php', 'SMTP.php'];
        foreach ($files as $f) {
            $path = $base . '/' . $f;
            if (!is_file($path)) {
                throw new RuntimeException(
                    'PHPMailer mancante. Vedi INSTALL.md sezione "PHPMailer".'
                );
            }
            require_once $path;
        }
        self::$loaded = true;
    }

    public static function send(string $to, string $subject, string $body, bool $html = true): bool
    {
        self::load();

        $cfg  = $GLOBALS['config']['mail']  ?? [];
        $smtp = $cfg['smtp']                ?? [];

        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
        try {
            if (!empty($smtp['host'])) {
                $mail->isSMTP();
                $mail->Host       = $smtp['host'];
                $mail->Port       = (int)($smtp['port'] ?? 587);
                $mail->SMTPAuth   = !empty($smtp['username']);
                $mail->Username   = $smtp['username'] ?? '';
                $mail->Password   = $smtp['password'] ?? '';
                $enc = $smtp['encryption'] ?? 'tls';
                if ($enc === 'tls') $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                if ($enc === 'ssl') $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
                $mail->SMTPAutoTLS = true;
            } else {
                $mail->isMail();
            }

            $mail->CharSet  = 'UTF-8';
            $mail->Encoding = 'base64';
            $mail->setFrom(
                $cfg['from_address'] ?? 'noreply@localhost',
                $cfg['from_name']    ?? (defined('APP_NAME') ? APP_NAME : 'App')
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
            }
            return $ok;
        } catch (\Throwable $e) {
            Logger::error('Mail send failed: ' . $e->getMessage(), ['to' => $to]);
            return false;
        }
    }
}
