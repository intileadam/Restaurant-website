<?php
declare(strict_types=1);

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$autoloadPaths = [
    __DIR__ . '/vendor/autoload.php',
    dirname(__DIR__) . '/vendor/autoload.php',
    dirname(__DIR__, 2) . '/vendor/autoload.php',
];
$autoloadLoaded = false;
foreach ($autoloadPaths as $autoload) {
    if (is_file($autoload)) {
        require $autoload;
        $autoloadLoaded = true;
        break;
    }
}
if (!$autoloadLoaded) {
    http_response_code(500);
    echo 'error';
    exit;
}

use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

/**
 * @return non-empty-string
 */
function sanitize_customer_table(string $raw, string $fallback = 'CUSTOMERS'): string
{
    $trimmed = trim($raw);
    if ($trimmed === '' || !preg_match('/^[A-Za-z0-9_]+$/', $trimmed)) {
        return $fallback;
    }
    return $trimmed;
}

/**
 * @param mixed $value
 */
function env_str(string $key, string $default = ''): string
{
    $v = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
    if ($v === false || $v === null || $v === '') {
        return $default;
    }
    return (string) $v;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo 'error';
    exit;
}

$recaptchaSecret = env_str('RECAPTCHA_SECRET_KEY');
$recaptchaResponse = isset($_POST['g-recaptcha-response']) ? trim((string) $_POST['g-recaptcha-response']) : '';
if ($recaptchaSecret === '' || $recaptchaResponse === '') {
    http_response_code(400);
    echo 'captcha';
    exit;
}

$verifyUrl = 'https://www.google.com/recaptcha/api/siteverify'
    . '?secret=' . rawurlencode($recaptchaSecret)
    . '&response=' . rawurlencode($recaptchaResponse);
$verifyRaw = @file_get_contents($verifyUrl);
$verifyData = $verifyRaw !== false ? json_decode($verifyRaw) : null;
if (!$verifyData || empty($verifyData->success)) {
    http_response_code(400);
    echo 'captcha';
    exit;
}

$firstname = trim((string) ($_POST['firstname'] ?? ''));
$lastname = trim((string) ($_POST['lastname'] ?? ''));
$emailRaw = trim((string) ($_POST['email'] ?? ''));
$email = filter_var($emailRaw, FILTER_SANITIZE_EMAIL);
$phone = trim((string) ($_POST['phone'] ?? ''));

if ($firstname === '') {
    http_response_code(400);
    echo 'validation';
    exit;
}

if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo 'validation';
    exit;
}

$tz = new DateTimeZone('America/Los_Angeles');
$now = new DateTime('now', $tz);
$comments = 'Website mailing list signup — ' . $now->format('Y-m-d');

$dbHost = env_str('DB_HOST', 'localhost');
$dbUser = env_str('DB_USER');
$dbPass = env_str('DB_PASS', env_str('DB_PASSWORD'));
$dbName = env_str('DB_NAME');
$dbPort = (int) env_str('DB_PORT', '3306');
$table = sanitize_customer_table(env_str('DB_CUSTOMER_TABLE', 'CUSTOMERS'));

if ($dbUser === '' || $dbName === '') {
    http_response_code(500);
    echo 'error';
    exit;
}

try {
    $conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName, $dbPort);
    $conn->set_charset('utf8mb4');
} catch (mysqli_sql_exception $e) {
    http_response_code(500);
    echo 'error';
    exit;
}

$sqlTable = '`' . str_replace('`', '', $table) . '`';

try {
    $dup = $conn->prepare("SELECT 1 FROM {$sqlTable} WHERE LOWER(EMAIL) = LOWER(?) LIMIT 1");
    $dup->bind_param('s', $email);
    $dup->execute();
    if ($dup->get_result()->fetch_row()) {
        $dup->close();
        $conn->close();
        http_response_code(409);
        echo 'duplicate';
        exit;
    }
    $dup->close();
} catch (mysqli_sql_exception $e) {
    $conn->close();
    http_response_code(500);
    echo 'error';
    exit;
}

$company = '';
$token = bin2hex(random_bytes(32));

try {
    $stmt = $conn->prepare(
        "INSERT INTO {$sqlTable}
        (FIRSTNAME, LASTNAME, EMAIL, COMPANY, PHONE, COMMENTS, IS_SUBSCRIBED, UNSUBSCRIBE_TOKEN)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
    );
    $stmt->bind_param(
        'sssssss',
        $firstname,
        $lastname,
        $email,
        $company,
        $phone,
        $comments,
        $token
    );
    $stmt->execute();
    $stmt->close();
} catch (mysqli_sql_exception $e) {
    $conn->close();
    if (($e->errno ?? 0) === 1062) {
        http_response_code(409);
        echo 'duplicate';
        exit;
    }
    http_response_code(500);
    echo 'error';
    exit;
}

$conn->close();
echo 'success';
