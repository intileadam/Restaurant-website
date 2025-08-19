<!-- Make sure SPF, DKIM, and DMARC are configured for the domain. -->
<!-- Determine the best way to set the subscribe token -->
<!-- Secure this page so that only mario can access it -->
 <!-- Test unsubscribe functionality -->

<?php
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$pdo = new PDO(
    "mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']}",
    $_ENV['DB_USER'],
    $_ENV['DB_PASS']
);

$batchSize = 10;
$pauseSeconds = 30;
$campaignDir = __DIR__ . '/campaigns';

function getCampaignFiles($dir): array {
    return array_values(array_filter(scandir($dir), fn($f) => is_file("$dir/$f") && pathinfo($f, PATHINFO_EXTENSION) === 'html'));
}

function appendUnsubscribe($html, $unsubscribeUrl): string {
    $block = <<<HTML
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; font-size: 12px; color: #888; text-align: center;">
        Don't want to hear from us again? 
        <a href="$unsubscribeUrl" style="color: #ff4d4d; font-weight: bold;">Unsubscribe</a>
    </div>
    HTML;
    return $html . $block;
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Send Campaign</title>
    <style>
        body { font-family: sans-serif; margin: 40px; }
        select, button, input[type=email], input[type=text] { font-size: 1rem; padding: 6px 10px; }
        .log { margin-top: 30px; white-space: pre-line; font-family: monospace; background: #f9f9f9; padding: 10px; border-radius: 6px; }
        iframe.preview { width: 100%; height: 600px; border: 1px solid #ccc; margin-top: 20px; }
        .confirm-warning { color: red; font-weight: bold; }
    </style>
</head>
<body>

<h2>📨 Send Campaign Email</h2>

<form method="POST">
    <label for="campaign">Select a campaign HTML file:</label><br><br>
    <select name="campaign" id="campaign" required>
        <option value="">-- Choose --</option>
        <?php foreach (getCampaignFiles($campaignDir) as $file): ?>
            <option value="<?= htmlspecialchars($file) ?>"><?= htmlspecialchars($file) ?></option>
        <?php endforeach; ?>
    </select>
    <br><br>

    <label>Choose recipients:</label><br>
    <input type="radio" name="recipientMode" value="TESTCUSTOMERS" required> Test Database<br>
    <input type="radio" name="recipientMode" value="CUSTOMERS" required> Real Customers (PROD) <br>
    <input type="radio" name="recipientMode" value="INDIVIDUAL" required> Individual Test Email<br>
    <br>

    <label for="testEmail">If sending individual, enter email:</label><br>
    <input type="email" name="testEmail" id="testEmail" placeholder="example@example.com" style="width: 300px;">
    <br><br>

    <div id="confirmBox">
        <label class="confirm-warning">If sending to real customers, type "CONFIRM SEND":</label><br>
        <input type="text" name="confirmSend" placeholder="Type here..." style="width: 300px;">
    </div>
    <br>

    <button type="submit" name="action" value="preview">Preview First Email</button>
    <button type="submit" name="action" value="send">Send to Selected</button>
</form>

<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['campaign'], $_POST['recipientMode'])) {
    $selectedFile = basename($_POST['campaign']);
    $campaignPath = "$campaignDir/$selectedFile";
    $recipientMode = $_POST['recipientMode'];
    $testEmail = filter_var($_POST['testEmail'] ?? '', FILTER_VALIDATE_EMAIL);
    $confirmSend = trim($_POST['confirmSend'] ?? '');
    $previewOnly = $_POST['action'] === 'preview';

    if (!file_exists($campaignPath)) {
        echo "<p style='color:red;'>❌ Campaign file not found.</p>";
        exit;
    }

    $htmlTemplate = file_get_contents($campaignPath);
    $customers = [];

    if ($recipientMode === 'INDIVIDUAL') {
        if (!$testEmail) {
            echo "<p style='color:red;'>❌ You must enter a valid test email.</p>";
            exit;
        }
        // Use dummy unsubscribe token
        $customers[] = [
            'EMAIL' => $testEmail,
            'FIRSTNAME' => 'Friend',
            'UNSUBSCRIBE_TOKEN' => bin2hex(random_bytes(32)) // temporary token
        ];
    } else {
        // Confirm sending to real customers
        if ($recipientMode === 'CUSTOMERS' && $_POST['action'] === 'send') {
            if (strtoupper($confirmSend) !== 'CONFIRM SEND') {
                echo "<p class='confirm-warning'>❌ You must type 'CONFIRM SEND' to send to real customers.</p>";
                exit;
            }
        }

        $table = preg_replace('/[^A-Z_]/', '', $recipientMode); // sanitize
        $query = "SELECT EMAIL, FIRSTNAME, UNSUBSCRIBE_TOKEN FROM $table WHERE EMAIL IS NOT NULL AND IS_SUBSCRIBED = 1";
        if ($previewOnly) $query .= " LIMIT 1";
        $stmt = $pdo->query($query);
        $customers = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (!$customers) {
            echo "<p style='color:red;'>❌ No customers found in $table.</p>";
            exit;
        }
    }

    if ($previewOnly) {
        $customer = $customers[0];
        $email = $customer['EMAIL'];
        $name = $customer['FIRSTNAME'] ?? 'there';
        $token = $customer['UNSUBSCRIBE_TOKEN'];
        $unsubscribeURL = "https://casadelpollo.com/unsubscribe.php?token=$token";
        $finalHtml = appendUnsubscribe($htmlTemplate, $unsubscribeURL);

        echo "<h3>📤 Preview (to: $email)</h3>";
        echo "<iframe class='preview' srcdoc='" . htmlspecialchars($finalHtml, ENT_QUOTES) . "'></iframe>";

        if ($recipientMode === 'INDIVIDUAL') {
            try {
                $mail = new PHPMailer(true);
                $mail->isSMTP();
                $mail->Host = $_ENV['SMTP_HOST'];
                $mail->SMTPAuth = true;
                $mail->Username = $_ENV['EMAIL_USER'];
                $mail->Password = $_ENV['EMAIL_PASSWORD'];
                $mail->Port = 587;
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;

                $mail->setFrom('mario@casadelpollo.com', $_ENV['FROM_NAME']);
                $mail->addAddress($testEmail);
                $mail->isHTML(true);
                $mail->Subject = '[PREVIEW] New Menu Email';
                $mail->Body = $finalHtml;

                $mail->send();
                echo "<p style='color:green;'>✅ Preview sent to <strong>$testEmail</strong></p>";
            } catch (Exception $e) {
                echo "<p style='color:red;'>❌ Failed to send preview: {$mail->ErrorInfo}</p>";
            }
        }

        echo "<p>✅ This is how the email will look (including unsubscribe link).</p>";
    } else {
        echo "<div class='log'><strong>Sending from:</strong> $selectedFile\n<strong>Recipient mode:</strong> $recipientMode\n\n";

        $count = 0;
        foreach ($customers as $customer) {
            $email = $customer['EMAIL'];
            $name = $customer['FIRSTNAME'] ?? 'there';
            $token = $customer['UNSUBSCRIBE_TOKEN'];
            $unsubscribeURL = "https://casadelpollo.com/unsubscribe.php?token=$token";
            $finalHtml = appendUnsubscribe($htmlTemplate, $unsubscribeURL);

            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host = $_ENV['SMTP_HOST'];
                $mail->SMTPAuth = true;
                $mail->Username = $_ENV['EMAIL_USER'];
                $mail->Password = $_ENV['EMAIL_PASSWORD'];
                $mail->Port = 587;

                $mail->setFrom('mario@casadelpollo.com', $_ENV['FROM_NAME']);
                $mail->addAddress($email);
                $mail->isHTML(true);
                $mail->Subject = 'Check out our new menu!';
                $mail->Body = $finalHtml;

                $mail->send();
                echo "✅ Sent to $email\n";
            } catch (Exception $e) {
                echo "❌ Failed for $email: {$mail->ErrorInfo}\n";
            }

            $count++;
            if ($count % $batchSize === 0) {
                echo "⏸ Pausing for $pauseSeconds seconds...\n";
                flush();
                sleep($pauseSeconds);
            }
        }

        echo "\nDone.</div>";
    }
}
?>

</body>
</html>
