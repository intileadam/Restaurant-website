<?php
require 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$pdo = new PDO(
    "mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']}",
    $_ENV['DB_USER'],
    $_ENV['DB_PASS']
);

$token = $_GET['token'] ?? '';

if (!$token) {
    http_response_code(400);
    exit("Invalid request.");
}

$stmt = $pdo->prepare("UPDATE TESTCUSTOMERS SET is_subscribed = 0 WHERE unsubscribe_token = ?");
$stmt->execute([$token]);

if ($stmt->rowCount() > 0) {
    echo "You've been unsubscribed successfully.";
} else {
    echo "Invalid or expired unsubscribe link.";
}
?>
