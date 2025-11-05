<?php
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $recaptchaSecret = $_ENV['RECAPTCHA_SECRET_KEY'];
    $recaptchaResponse = $_POST['g-recaptcha-response'];

    $verifyResponse = file_get_contents(
        "https://www.google.com/recaptcha/api/siteverify?secret=$recaptchaSecret&response=$recaptchaResponse"
    );
    
    $responseData = json_decode($verifyResponse);
    if (!$responseData->success) {
        http_response_code(400);
        echo "Captcha validation failed.";
        exit;
    }

    $name    = htmlspecialchars(trim($_POST["name"]));
    $email   = filter_var(trim($_POST["email"]), FILTER_SANITIZE_EMAIL);
    $phone   = htmlspecialchars(trim($_POST["phone"]));
    $message = htmlspecialchars(trim($_POST["message"]));

    // Check fields
    if (empty($name) || empty($email) || empty($phone) || empty($message)) {
        echo "Please fill out all fields.";
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "Please enter a valid email address.";
    exit;
    }

    // Create mail object
    $mail = new PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.dreamhost.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = $_ENV['EMAIL_USER'];
        $mail->Password   = $_ENV['EMAIL_PASSWORD'];
        $mail->Port       = $_ENV['SMTP_PORT'];

        // Recipients
        $mail->setFrom('mario@casadelpollo.com', 'Contact request from casadelpollo.com'); // the address sending the email
        $mail->addAddress('mario@casadelpollo.com'); // the recipient
        $mail->addReplyTo($email, $name); // the customer's address


        // Content
        $mail->isHTML(false);
        $mail->Subject = 'New contact form submission'; // subject
        $mail->Body    =
            "Name: $name\n" .
            "Email: $email\n" .
            "Phone: $phone\n\n" .
            "Message:\n$message";

        if ($mail->send()) {
            echo "success";  // This means email sent successfully
        } else {
            http_response_code(500);  // Set an error HTTP code
            echo "error";  // Email failed to send
        }
        
    } catch (Exception $e) {
        echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
    }
} else {
    echo "Invalid request.";
}
