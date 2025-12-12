<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0'); // flip to '1' if you want to see the error in the browser
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/php-error.log');
file_put_contents(__DIR__ . '/php-debug.log', date('c') . " " . ($_SERVER['REQUEST_URI'] ?? '') . PHP_EOL, FILE_APPEND);

// Try to load Composer autoloader from the most common locations (docroot or repo root).
$autoloadPaths = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
];
foreach ($autoloadPaths as $autoload) {
    if (file_exists($autoload)) {
        require_once $autoload;
        break;
    }
}

// Load environment variables from .env if phpdotenv is available.
if (class_exists(\Dotenv\Dotenv::class)) {
    $envDir = file_exists(__DIR__ . '/../.env') ? dirname(__DIR__) : __DIR__;
    if (file_exists($envDir . '/.env')) {
        \Dotenv\Dotenv::createImmutable($envDir)->safeLoad();
    }
} else {
    // Minimal fallback .env loader so we still get DB settings without phpdotenv.
    $envDir = file_exists(__DIR__ . '/../.env') ? dirname(__DIR__) : __DIR__;
    $envPath = $envDir . '/.env';
    if (is_file($envPath) && is_readable($envPath)) {
        $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines !== false) {
            foreach ($lines as $line) {
                if (str_starts_with(trim($line), '#')) {
                    continue;
                }
                $parts = explode('=', $line, 2);
                if (count($parts) === 2) {
                    $key = trim($parts[0]);
                    $value = trim($parts[1], " \t\n\r\0\x0B\"'");
                    $_ENV[$key] = $value;
                    $_SERVER[$key] = $value;
                }
            }
        }
    }
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

function envValue(string $key, mixed $default = null): mixed
{
    return $_ENV[$key] ?? $_SERVER[$key] ?? $default;
}

function db(): mysqli
{
    $host = (string) envValue('DB_HOST', 'localhost');
    $user = (string) envValue('DB_USER', '');
    $pass = (string) envValue('DB_PASS', envValue('DB_PASSWORD', ''));
    $name = (string) envValue('DB_NAME', '');
    $port = (int) envValue('DB_PORT', 3306);

    // Log connection target to help debug prod issues.
    file_put_contents(__DIR__ . '/php-debug.log', date('c') . " connecting to {$host}:{$port} db={$name}" . PHP_EOL, FILE_APPEND);

    $conn = new mysqli($host, $user, $pass, $name, $port);
    $conn->set_charset('utf8mb4');
    return $conn;
}

function render(string $template, array $data = [], int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    extract($data, EXTR_SKIP);
    $candidates = [
        __DIR__ . '/templates/' . $template . '.php',
        __DIR__ . '/templates/' . $template . '.html', // fallback for existing HTML templates
    ];
    foreach ($candidates as $file) {
        if (is_file($file)) {
            include $file;
            exit;
        }
    }
    echo 'Template not found';
    exit;
}

function getToken(): string
{
    return isset($_GET['token']) ? trim((string) $_GET['token']) : '';
}

function handleUnsubscribe(): void
{
    $token = getToken();
    if ($token === '') {
        render('error', ['message' => ''], 400);
    }

    try {
        $conn = db();
        $statusStmt = $conn->prepare('SELECT IS_SUBSCRIBED FROM TESTCUSTOMERS WHERE UNSUBSCRIBE_TOKEN = ? LIMIT 1');
        $statusStmt->bind_param('s', $token);
        $statusStmt->execute();
        $statusStmt->bind_result($currentStatus);
        $hasRow = $statusStmt->fetch();
        $statusStmt->close();

        if (!$hasRow) {
            render('error', ['message' => 'Invalid unsubscribe link.'], 404);
        }

        if ((int) $currentStatus === 0) {
            render('unsubscribed', [
                'rejoined' => false,
                'token' => $token,
                'alreadyUnsubscribed' => true,
            ]);
        }

        $stmt = $conn->prepare('UPDATE TESTCUSTOMERS SET IS_SUBSCRIBED = 0 WHERE UNSUBSCRIBE_TOKEN = ?');
        $stmt->bind_param('s', $token);
        $stmt->execute();

        render('unsubscribed', ['rejoined' => false, 'token' => $token, 'alreadyUnsubscribed' => false]);
    } catch (Throwable $e) {
        file_put_contents(__DIR__ . '/php-error.log', date('c') . ' unsubscribe error: ' . $e->getMessage() . PHP_EOL, FILE_APPEND);
        render('error', ['message' => $e->getMessage()], 500);
    }
}

function handleResubscribe(): void
{
    $token = getToken();
    if ($token === '') {
        render('error', ['message' => ''], 400);
    }

    try {
        $conn = db();
        $stmt = $conn->prepare('UPDATE TESTCUSTOMERS SET IS_SUBSCRIBED = 1 WHERE UNSUBSCRIBE_TOKEN = ?');
        $stmt->bind_param('s', $token);
        $stmt->execute();

        if ($stmt->affected_rows === 0) {
            render('error', ['message' => 'Invalid token.'], 404);
        }

        render('unsubscribed', ['rejoined' => true, 'token' => $token, 'alreadyUnsubscribed' => false]);
    } catch (Throwable $e) {
        file_put_contents(__DIR__ . '/php-error.log', date('c') . ' resubscribe error: ' . $e->getMessage() . PHP_EOL, FILE_APPEND);
        render('error', ['message' => $e->getMessage()], 500);
    }
}

function handleHealthz(): void
{
    http_response_code(200);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'ok';
    exit;
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?: '/';
$normalizedPath = rtrim($path, '/');
if ($normalizedPath === '') {
    $normalizedPath = '/';
}

switch ($normalizedPath) {
    case '/':
        header('Location: /unsubscribe', true, 302);
        exit;
    case '/unsubscribe':
        handleUnsubscribe();
        break;
    case '/resubscribe':
        handleResubscribe();
        break;
    case '/healthz':
        handleHealthz();
        break;
    default:
        http_response_code(404);
        echo 'Not found';
}
