# PHPMailer (vendored)

This folder must contain a copy of [PHPMailer](https://github.com/PHPMailer/PHPMailer)
so the auth module can send transactional emails (magic-link, etc.) without Composer.

## Required files

Download the latest stable release zip from
<https://github.com/PHPMailer/PHPMailer/releases> and place ONLY the contents
of its `src/` folder here:

```
system/lib/PHPMailer/
  README.md            (this file)
  src/
    Exception.php
    PHPMailer.php
    SMTP.php
    POP3.php           (optional, not used)
    OAuth.php          (optional, not used)
```

The minimum classes loaded by `system/Mailer.php` are:

- `PHPMailer\PHPMailer\Exception`
- `PHPMailer\PHPMailer\PHPMailer`
- `PHPMailer\PHPMailer\SMTP`

## Verification

After copying, the following file MUST exist:

```
system/lib/PHPMailer/src/PHPMailer.php
```

If it does not, `Mailer::send()` throws `RuntimeException`.

## Why vendored, not Composer

This template targets cPanel shared hosting where Composer is often unavailable.
Vendoring keeps the module zero-dependency and rsync/FTP-deployable.

## License

PHPMailer is distributed under the LGPL-2.1 License. The license file is included
in the upstream zip and must remain alongside the source files.
