<?php
if (!defined('SECURE_ACCESS')) die;

/**
 * Env
 * --------------------------------------------------------------------
 * Helper centralizzato per la lettura di APP_ENV. Sostituisce
 *   defined('APP_ENV') && APP_ENV === 'development'
 * sparso per il codice (Mailer, Models, BaseController, front-controller,
 * cron). Read-only.
 * --------------------------------------------------------------------
 */
final class Env
{
    public static function name(): string
    {
        return defined('APP_ENV') ? (string)APP_ENV : 'production';
    }

    public static function isDev(): bool
    {
        return self::name() === 'development';
    }

    public static function isProd(): bool
    {
        return self::name() === 'production';
    }
}
