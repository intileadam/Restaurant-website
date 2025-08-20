<?php
require 'vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

// ---- PDO with sane defaults ----
try {
    $dsn = sprintf(
        "mysql:host=%s;dbname=%s;port=%s;charset=utf8mb4",
        $_ENV['DB_HOST'] ?? '127.0.0.1',
        $_ENV['DB_NAME'] ?? '',
        $_ENV['DB_PORT'] ?? '3306'
    );
    $pdo = new PDO($dsn, $_ENV['DB_USER'] ?? '', $_ENV['DB_PASS'] ?? '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
} catch (Throwable $e) {
    http_response_code(500);
    echo renderPage("We’re having trouble right now. Please try again later.", false);
    exit;
}

// ---- Read + validate token ----
$token = $_GET['token'] ?? '';
$token = trim($token);

// Token should be a 64-char hex string (from bin2hex(random_bytes(32)))
if ($token === '' || !preg_match('/^[A-Fa-f0-9]{64}$/', $token)) {
    http_response_code(400);
    echo renderPage("Invalid unsubscribe link.", false);
    exit;
}

/**
 * Try to unsubscribe in one table; return:
 * - 'unsubscribed' if we just flipped the flag
 * - 'already' if token exists but was already unsubscribed
 * - 'none' if token not found in this table
 */
function tryUnsubscribe(PDO $pdo, string $table, string $token): string {
    // 1) Attempt to set IS_SUBSCRIBED = 0
    // Column names here match your sender script casing (MySQL is case-insensitive for columns)
    $updateSql = "UPDATE `$table` SET `IS_SUBSCRIBED` = 0 WHERE `UNSUBSCRIBE_TOKEN` = ? AND `IS_SUBSCRIBED` = 1";
    $stmt = $pdo->prepare($updateSql);
    $stmt->execute([$token]);
    if ($stmt->rowCount() > 0) {
        return 'unsubscribed';
    }

    // 2) Check if the token exists at all (maybe already unsubscribed)
    $checkSql = "SELECT 1 FROM `$table` WHERE `UNSUBSCRIBE_TOKEN` = ? LIMIT 1";
    $check = $pdo->prepare($checkSql);
    $check->execute([$token]);
    if ($check->fetchColumn()) {
        return 'already';
    }

    // 3) Not found in this table
    return 'none';
}

// Try prod first, then test (order doesn’t really matter; choose what you prefer)
$tables = ['CUSTOMERS', 'TESTCUSTOMERS'];

$result = 'none';
foreach ($tables as $t) {
    $outcome = tryUnsubscribe($pdo, $t, $token);
    if ($outcome !== 'none') {
        $result = $outcome;
        break;
    }
}

// ---- Render friendly page ----
switch ($result) {
    case 'unsubscribed':
        echo renderPage("You’ve been unsubscribed successfully. We’re sorry to see you go!");
        break;
    case 'already':
        echo renderPage("You’re already unsubscribed. No further emails will be sent.");
        break;
    default:
        // Don’t reveal whether the token exists in either table—just a generic message.
        echo renderPage("This unsubscribe link is invalid or has expired.", false);
        break;
}

/** ---- Simple HTML page renderer ---- */
function renderPage(string $message, bool $success = true): string {
    $title = $success ? "Unsubscribed" : "Unsubscribe";
    $color = $success ? "#0a7d27" : "#b00020";
    $icon  = $success ? "✅" : "⚠️";
    // Optional: set a brand name/address below
    $brand = "Casa del Pollo";

    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{$title} – {$brand}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f7f7f7; margin:0; padding:32px; }
  .card { max-width: 560px; margin: 0 auto; background:#fff; padding: 24px; border-radius: 10px; box-shadow: 0 6px 24px rgba(0,0,0,0.06); }
  h1 { margin: 0 0 12px; font-size: 22px; color: #333; }
  p { color: #444; line-height: 1.5; }
  .status { color: {$color}; font-weight: 600; margin-bottom: 8px; }
  .brand { margin-top: 24px; font-size: 12px; color: #777; }
  .btn { display:inline-block; margin-top: 16px; padding:10px 16px; background:#333; color:#fff; text-decoration:none; border-radius:6px; }
</style>
</head>
<body>
  <div class="card">
    <div class="status">{$icon} {$title}</div>
    <h1>{$brand}</h1>
    <p>{$message}</p>
    <a class="btn" href="/">Return to website</a>
    <div class="brand">© {$brand}</div>
  </div>
</body>
</html>
HTML;
}
