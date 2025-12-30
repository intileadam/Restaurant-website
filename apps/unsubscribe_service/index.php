<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

loadEnvironment();
ini_set('error_log', storage_path('php-error.log'));

// Try to load Composer autoloader from the most common locations (docroot or repo root).
$autoloadPaths = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
    dirname(__DIR__, 2) . '/vendor/autoload.php',
];
foreach ($autoloadPaths as $autoload) {
    if (file_exists($autoload)) {
        require_once $autoload;
        break;
    }
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

function storage_directory(): string
{
    static $dir = null;
    if ($dir !== null) {
        return $dir;
    }
    $candidate = getenv('CDP_UNSUB_STORAGE_DIR');
    if (!$candidate) {
        $candidate = dirname(__DIR__) . '/var/unsubscribe';
    }
    if (!is_dir($candidate)) {
        @mkdir($candidate, 0750, true);
    }
    if (!is_dir($candidate) || !is_writable($candidate)) {
        $candidate = sys_get_temp_dir();
    }
    $dir = rtrim($candidate, DIRECTORY_SEPARATOR);
    return $dir;
}

function storage_path(string $filename): string
{
    return storage_directory() . DIRECTORY_SEPARATOR . ltrim($filename, DIRECTORY_SEPARATOR);
}

function loadEnvironment(): void
{
    $envFile = resolveEnvFile();
    if (!$envFile) {
        return;
    }
    if (class_exists(\Dotenv\Dotenv::class)) {
        \Dotenv\Dotenv::createImmutable(dirname($envFile), basename($envFile))->safeLoad();
        return;
    }
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }
    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            continue;
        }
        [$key, $value] = array_pad(explode('=', $trimmed, 2), 2, '');
        $key = trim($key);
        $value = trim($value, " \t\n\r\0\x0B\"'");
        if ($key === '') {
            continue;
        }
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
        putenv("{$key}={$value}");
    }
}

function resolveEnvFile(): ?string
{
    $explicit = getenv('CDP_UNSUB_ENV_FILE');
    $candidates = [];
    if ($explicit) {
        $candidates[] = $explicit;
    }
    $candidates[] = __DIR__ . '/.env';
    $candidates[] = dirname(__DIR__) . '/config/unsubscribe.env';
    $candidates[] = dirname(__DIR__) . '/.env';
    foreach ($candidates as $candidate) {
        if (!$candidate) {
            continue;
        }
        if (is_file($candidate) && is_readable($candidate)) {
            return $candidate;
        }
    }
    return null;
}

function envValue(string $key, mixed $default = null): mixed
{
    $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
    if ($value === false || $value === null) {
        return $default;
    }
    return $value;
}

function db(): mysqli
{
    $host = (string) envValue('DB_HOST', 'localhost');
    $user = (string) envValue('DB_USER', '');
    $pass = (string) envValue('DB_PASS', envValue('DB_PASSWORD', ''));
    $name = (string) envValue('DB_NAME', '');
    $port = (int) envValue('DB_PORT', 3306);
    $conn = new mysqli($host, $user, $pass, $name, $port);
    $conn->set_charset('utf8mb4');
    return $conn;
}

function sanitize_table(string $table, string $fallback): string
{
    $trimmed = trim($table);
    if ($trimmed === '' || !preg_match('/^[A-Za-z0-9_]+$/', $trimmed)) {
        return $fallback;
    }
    return $trimmed;
}

function production_table(): string
{
    static $table = null;
    if ($table !== null) {
        return $table;
    }
    $table = sanitize_table((string) envValue('DB_CUSTOMER_TABLE', 'CUSTOMERS'), 'CUSTOMERS');
    return $table;
}

function test_table(): string
{
    static $table = null;
    if ($table !== null) {
        return $table;
    }
    $table = sanitize_table((string) envValue('DB_TEST_CUSTOMER_TABLE', 'TESTCUSTOMERS'), 'TESTCUSTOMERS');
    return $table;
}

function resolve_table_for_request(): string
{
    $mode = isset($_GET['mode']) ? strtolower(trim((string) $_GET['mode'])) : '';
    if ($mode === 'test') {
        return test_table();
    }
    return production_table();
}

function render(string $template, array $data = [], int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    extract($data, EXTR_SKIP);
    $candidates = [
        __DIR__ . '/templates/' . $template . '.php',
        __DIR__ . '/templates/' . $template . '.html',
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

function readToken(): string
{
    $token = isset($_GET['token']) ? trim((string) $_GET['token']) : '';
    if ($token === '') {
        return '';
    }
    if (!preg_match('/^[A-Fa-f0-9]{64}$/', $token)) {
        return '';
    }
    return $token;
}

function logAuditEvent(string $action, string $token, bool $success): void
{
    $tokenHash = $token !== '' ? substr(hash('sha256', $token), 0, 12) : '-';
    $ip = $_SERVER['REMOTE_ADDR'] ?? '-';
    $line = sprintf(
        "%s action=%s success=%s token=%s ip=%s",
        date('c'),
        $action,
        $success ? 'true' : 'false',
        $tokenHash,
        $ip
    );
    @file_put_contents(storage_path('audit.log'), $line . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function handleUnsubscribe(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        http_response_code(405);
        exit;
    }
    $token = readToken();
    if ($token === '') {
        logAuditEvent('unsubscribe.missing_token', '', false);
        render('error', ['message' => 'Invalid unsubscribe link.'], 400);
    }

    try {
        $conn = db();
        $table = resolve_table_for_request();
        $escapedTable = '`' . $table . '`';
        $statusStmt = $conn->prepare("SELECT IS_SUBSCRIBED FROM {$escapedTable} WHERE UNSUBSCRIBE_TOKEN = ? LIMIT 1");
        $statusStmt->bind_param('s', $token);
        $statusStmt->execute();
        $statusStmt->bind_result($currentStatus);
        $hasRow = $statusStmt->fetch();
        $statusStmt->close();

        if (!$hasRow) {
            logAuditEvent('unsubscribe.invalid_token', $token, false);
            render('error', ['message' => 'Invalid unsubscribe link.'], 404);
        }

        if ((int) $currentStatus === 0) {
            logAuditEvent('unsubscribe.already_processed', $token, true);
            render('unsubscribed', [
                'rejoined' => false,
                'token' => $token,
                'alreadyUnsubscribed' => true,
            ]);
        }

        $stmt = $conn->prepare("UPDATE {$escapedTable} SET IS_SUBSCRIBED = 0 WHERE UNSUBSCRIBE_TOKEN = ?");
        $stmt->bind_param('s', $token);
        $stmt->execute();

        if ($stmt->affected_rows === 0) {
            logAuditEvent('unsubscribe.noop', $token, false);
            render('error', ['message' => 'Unable to process request.'], 500);
        }

        logAuditEvent('unsubscribe.success', $token, true);
        render('unsubscribed', ['rejoined' => false, 'token' => $token, 'alreadyUnsubscribed' => false]);
    } catch (Throwable $e) {
        logAuditEvent('unsubscribe.error', $token, false);
        error_log('unsubscribe error: ' . $e->getMessage());
        render('error', ['message' => 'Unable to process your request right now.'], 500);
    }
}

function handleResubscribe(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
        http_response_code(405);
        exit;
    }
    $token = readToken();
    if ($token === '') {
        logAuditEvent('resubscribe.missing_token', '', false);
        render('error', ['message' => 'Invalid resubscribe link.'], 400);
    }

    try {
        $conn = db();
        $table = resolve_table_for_request();
        $escapedTable = '`' . $table . '`';
        $stmt = $conn->prepare("UPDATE {$escapedTable} SET IS_SUBSCRIBED = 1 WHERE UNSUBSCRIBE_TOKEN = ?");
        $stmt->bind_param('s', $token);
        $stmt->execute();

        if ($stmt->affected_rows === 0) {
            logAuditEvent('resubscribe.invalid_token', $token, false);
            render('error', ['message' => 'Invalid token.'], 404);
        }

        logAuditEvent('resubscribe.success', $token, true);
        render('unsubscribed', ['rejoined' => true, 'token' => $token, 'alreadyUnsubscribed' => false]);
    } catch (Throwable $e) {
        logAuditEvent('resubscribe.error', $token, false);
        error_log('resubscribe error: ' . $e->getMessage());
        render('error', ['message' => 'Unable to process your request right now.'], 500);
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
