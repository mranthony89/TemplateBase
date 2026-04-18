<?php if (!defined('SECURE_ACCESS')) die; ?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($title ?? 'Template Base') ?></title>
</head>
<body>
    <main>
        <h1><?= h($title ?? '') ?></h1>
        <p><?= h($message ?? '') ?></p>

        <!--
            Esempio form POST protetto da CSRF.
            Tutti i campi di output utente passano da h() per prevenire XSS.
        -->
        <form method="POST" action="/dashboard/update">
            <?= CSRF::field() ?>
            <label for="email">Nuova email</label>
            <input type="email" id="email" name="email" required>
            <button type="submit">Salva</button>
        </form>
    </main>
</body>
</html>
