<?php
/**
 * Local-only Campaign Sender
 * - Consolidated live preview (subject-aware)
 * - Lint gating (block send unless override)
 * - CSS inlining (optional: tijsverkoyen/css-to-inline-styles)
 * - Per-recipient List-Unsubscribe (incl. One-Click)
 * - SMTP preflight + keep-alive, streaming recipients
 * - Detailed on-page logging + optional summary email + CSV failures
 *
 * How to run:
 *   php -S 127.0.0.1:8000
 *   open http://127.0.0.1:8000/send_emails.php
 */

require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use TijsVerkoyen\CssToInlineStyles\CssToInlineStyles;

/* ---------- Local-only access guard ---------- */
$remote = $_SERVER['REMOTE_ADDR'] ?? 'cli';
if (!in_array($remote, ['127.0.0.1', '::1', 'cli'])) {
    http_response_code(403);
    exit('Forbidden: local access only.');
}

/* ---------- Env ---------- */
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

function envr(string $key, $default = null, bool $required = false) {
    $val = $_ENV[$key] ?? $default;
    if ($required && ($val === null || $val === '')) {
        http_response_code(500);
        echo "<pre>Missing required env: $key</pre>";
        exit;
    }
    return $val;
}

$dbHost   = envr('DB_HOST', '127.0.0.1', true);
$dbName   = envr('DB_NAME', null, true);
$dbUser   = envr('DB_USER', null, true);
$dbPass   = envr('DB_PASS', null, true);
$dbPort   = envr('DB_PORT', '3306');

$smtpHost = envr('SMTP_HOST', null, true);
$smtpUser = envr('EMAIL_USER', null, true);
$smtpPass = envr('EMAIL_PASSWORD', null, true);
$fromAddr = envr('FROM_EMAIL', 'no-reply@localhost');
$fromName = envr('FROM_NAME', 'Local Campaign Sender');

$smtpPort     = (int) envr('SMTP_PORT', '587');
$smtpSecurity = strtoupper(envr('SMTP_SECURITY', 'STARTTLS')); // STARTTLS or SMTPS

$unsubscribeBase = rtrim(envr('UNSUBSCRIBE_BASE', 'https://casadelpollo.com'), '/');

$batchSize    = (int) envr('BATCH_SIZE', '10');
$pauseSeconds = (int) envr('PAUSE_SECONDS', '30');

$dkimDomain    = envr('DKIM_DOMAIN', null);
$dkimSelector  = envr('DKIM_SELECTOR', null);
$dkimIdentity  = envr('DKIM_IDENTITY', null);
$dkimKeyPath   = envr('DKIM_PRIVATE_KEY', null); // path to private key

$campaignDir = __DIR__ . '/campaigns';

/* ---------- PDO ---------- */
try {
    $dsn = "mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset=utf8mb4";
    $pdo = new PDO($dsn, $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
} catch (PDOException $e) {
    http_response_code(500);
    echo "<pre>Database connection failed: {$e->getMessage()}</pre>";
    exit;
}

/* ---------- Helpers: template processing & lint ---------- */
function getCampaignFiles($dir): array {
    if (!is_dir($dir)) return [];
    $all = scandir($dir) ?: [];
    return array_values(array_filter($all, fn($f) => is_file("$dir/$f") && strtolower(pathinfo($f, PATHINFO_EXTENSION)) === 'html'));
}

function appendUnsubscribe(string $html, string $unsubscribeUrl): string {
    $hasUnsub = (stripos($html, '/unsubscribe.php') !== false) || preg_match('~>[^<]*unsubscrib~i', $html);
    if ($hasUnsub) return $html;

    $block = <<<HTML
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; font-size: 12px; color: #888; text-align: center;">
        Don't want to hear from us again?
        <a href="$unsubscribeUrl" style="color: #ff4d4d; font-weight: bold;">Unsubscribe</a>
    </div>
    HTML;

    if (stripos($html, '</body>') !== false) {
        return preg_replace('~</body>~i', $block . "\n</body>", $html, 1);
    }
    return $html . $block;
}

function ensureViewportMeta(string $html, array &$issues): string {
    if (!preg_match('~<meta[^>]+name=["\']viewport["\'][^>]*>~i', $html)) {
        $meta = '<meta name="viewport" content="width=device-width, initial-scale=1">';
        if (preg_match('~</head>~i', $html)) {
            $html = preg_replace('~</head>~i', $meta . "\n</head>", $html, 1);
        } else {
            $issues[] = ['severity' => 'warn', 'msg' => 'No <head> tag found; injected viewport meta at top.'];
            $html = $meta . $html;
        }
        $issues[] = ['severity' => 'warn', 'msg' => 'Added mobile viewport meta for better mobile rendering.'];
    }
    return $html;
}

function stripScripts(string $html, array &$issues): string {
    $cnt = 0;
    $html = preg_replace_callback(
        '~<script\b[^>]*>.*?</script>~is',
        function ($m) use (&$cnt) { $cnt++; return ''; },
        $html
    );
    if ($cnt > 0) {
        $issues[] = ['severity' => 'warn', 'msg' => "Removed {$cnt} <script> tag(s). Not supported in most email clients."];
    }
    return $html;
}

function removeExternalStyles(string $html, array &$issues): string {
    $matches = [];
    preg_match_all('~<link[^>]+rel=["\']stylesheet["\'][^>]*>~i', $html, $matches);
    if (!empty($matches[0])) {
        $issues[] = ['severity' => 'warn', 'msg' => "Removed ".count($matches[0])." external stylesheet link(s). Not supported in emails."];
        $html = preg_replace('~<link[^>]+rel=["\']stylesheet["\'][^>]*>~i', '', $html);
    }
    return $html;
}

function extractInlineableCSS(string $html, array &$issues): array {
    $css = '';
    $cnt = 0;
    $html = preg_replace_callback('~<style\b[^>]*>(.*?)</style>~is', function($m) use (&$css, &$cnt){ $cnt++; $css .= "\n".$m[1]; return ''; }, $html);
    if ($cnt > 0) $issues[] = ['severity' => 'warn', 'msg' => "Inlined CSS from {$cnt} <style> block(s)."];
    return [$html, $css];
}

function inlineCSS(string $html, string $css, array &$issues): string {
    if (!class_exists(\TijsVerkoyen\CssToInlineStyles\CssToInlineStyles::class)) {
        $issues[] = ['severity' => 'warn', 'msg' => 'CSS inliner not installed (tijsverkoyen/css-to-inline-styles). Run: composer require tijsverkoyen/css-to-inline-styles'];
        return $html;
    }

    $inliner = new \TijsVerkoyen\CssToInlineStyles\CssToInlineStyles();

    // Be defensive across library versions:
    if (method_exists($inliner, 'setEncoding')) {
        $inliner->setEncoding('UTF-8');
    }
    // Some versions support these; we only call them if present.
    if (method_exists($inliner, 'setCleanup')) {
        // false = keep existing inline styles as-is
        $inliner->setCleanup(false);
    }
    if (method_exists($inliner, 'setStripOriginalStyleTags')) {
        // We already extracted <style> blocks, but if any remain, strip them after inlining.
        $inliner->setStripOriginalStyleTags(true);
    }
    if (method_exists($inliner, 'setUseInlineStylesBlock')) {
        // Allow inlining from <style> blocks that may remain
        $inliner->setUseInlineStylesBlock(true);
    }

    try {
        return $inliner->convert($html, $css ?? '');
    } catch (\Throwable $e) {
        $issues[] = ['severity' => 'warn', 'msg' => 'CSS inliner failed: '.$e->getMessage()];
        return $html; // fall back to original
    }
}


function imageChecks(string $html, array &$issues): void {
    if (preg_match_all('~<img[^>]+src=["\'](?!https?://|cid:|data:|//)([^"\']+)["\']~i', $html, $m)) {
        $issues[] = ['severity' => 'warn', 'msg' => "Found ".count($m[0])." image(s) with relative URLs. Use absolute https:// URLs or CID embeds."];
    }
    if (preg_match_all('~<img(?![^>]*\balt=)[^>]*>~i', $html, $m)) {
        $issues[] = ['severity' => 'warn', 'msg' => "Found ".count($m[0])." <img> without alt. Add alt for accessibility & deliverability."];
    }
}

function cssBackgroundImageCheck(string $html, array &$issues): void {
    if (preg_match('~background-image\s*:\s*url\(~i', $html)) {
        $issues[] = ['severity' => 'warn', 'msg' => "Detected CSS background-image. Many clients strip it; prefer <img> tags."];
    }
}

function formCheck(string $html, array &$issues): void {
    if (stripos($html, '<form') !== false) {
        $issues[] = ['severity' => 'warn', 'msg' => "Found <form> tag(s). Forms are not widely supported in email."];
    }
}

function sizeCheck(string $html, array &$issues): void {
    $bytes = strlen($html);
    if ($bytes > 102400) {
        $kb = round($bytes / 1024, 1);
        $issues[] = ['severity' => 'warn', 'msg' => "HTML size is {$kb} KB. Gmail clips messages over ~102 KB."];
    }
}

function ensureSubjectPresent(string $subject, array &$issues): void {
    if (trim($subject) === '') {
        $issues[] = ['severity' => 'error', 'msg' => 'Subject is required.'];
    }
}

/**
 * Full processing pipeline:
 * - Remove scripts & external styles
 * - Extract <style> CSS and inline it
 * - Ensure viewport meta
 * - Append unsubscribe if missing
 * - Run checks that don't modify content
 */
function processTemplate(string $html, string $unsubscribeUrl, string $subject, array &$issues): string {
    ensureSubjectPresent($subject, $issues);
    $html = stripScripts($html, $issues);
    $html = removeExternalStyles($html, $issues);
    [$html, $css] = extractInlineableCSS($html, $issues);
    $html = inlineCSS($html, $css, $issues);
    $html = ensureViewportMeta($html, $issues);

    $before = $html;
    $html = appendUnsubscribe($html, $unsubscribeUrl);
    if ($before !== $html) {
        $issues[] = ['severity' => 'warn', 'msg' => 'Added unsubscribe block (none detected).'];
    }

    imageChecks($html, $issues);
    cssBackgroundImageCheck($html, $issues);
    formCheck($html, $issues);
    sizeCheck($html, $issues);

    return $html;
}

function buildMailer(
    string $smtpHost, string $smtpUser, string $smtpPass, int $smtpPort,
    string $smtpSecurity, string $fromAddr, string $fromName,
    ?string $dkimDomain, ?string $dkimSelector, ?string $dkimIdentity, ?string $dkimKeyPath
): PHPMailer {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = $smtpHost;
    $mail->SMTPAuth   = true;
    $mail->Username   = $smtpUser;
    $mail->Password   = $smtpPass;
    if ($smtpSecurity === 'SMTPS') {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;  // 465
    } else {
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; // 587
    }
    $mail->Port       = $smtpPort;
    $mail->setFrom($fromAddr, $fromName);
    $mail->addReplyTo($fromAddr, $fromName); // or a dedicated replies@ address
    $mail->Sender = $fromAddr;               // Return-Path (bounces)
    $mail->isHTML(true);
    $mail->CharSet = 'UTF-8';
    $mail->Timeout = 15;
    $mail->SMTPOptions = [
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ]
    ];

    if ($dkimDomain && $dkimSelector && $dkimKeyPath && is_readable($dkimKeyPath)) {
        $mail->DKIM_domain = $dkimDomain;
        $mail->DKIM_selector = $dkimSelector;
        $mail->DKIM_identity = $dkimIdentity ?: $fromAddr;
        $mail->DKIM_private = $dkimKeyPath;
    }
    return $mail;
}

/* ---------- LIVE PREVIEW (JSON-safe) ---------- */
if (isset($_GET['template_preview']) && isset($_GET['subject'])) {
    ini_set('display_errors', '0');
    ini_set('html_errors', '0');
    ob_start();

    try {
        $file = basename($_GET['template_preview']);
        $subject = (string)$_GET['subject'];
        // Subject hardening for preview too
        $subject = preg_replace('/[\r\n]+/', ' ', $subject);
        if (mb_strlen($subject) > 200) {
            $subject = mb_substr($subject, 0, 200) . '…';
        }

        $path = $campaignDir . '/' . $file;
        if (!is_file($path) || strtolower(pathinfo($path, PATHINFO_EXTENSION)) !== 'html') {
            http_response_code(404);
            $buffer = trim(ob_get_clean());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Template not found', 'buffer' => $buffer], JSON_INVALID_UTF8_SUBSTITUTE);
            exit;
        }

        $raw = file_get_contents($path);
        if ($raw === false) {
            http_response_code(500);
            $buffer = trim(ob_get_clean());
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Failed to read file', 'buffer' => $buffer], JSON_INVALID_UTF8_SUBSTITUTE);
            exit;
        }

        $issues = [];
        $dummyToken = str_repeat('A', 64);
        $unsubURL  = $unsubscribeBase . "/unsubscribe.php?token=" . $dummyToken;
        $final = processTemplate($raw, $unsubURL, $subject, $issues);

        $buffer = trim(ob_get_clean());
        header('Content-Type: application/json');
        echo json_encode([
            'html'    => $final,
            'issues'  => $issues,
            'buffer'  => $buffer ?: null,
        ], JSON_INVALID_UTF8_SUBSTITUTE);
    } catch (Throwable $e) {
        $buffer = trim(ob_get_clean());
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'error'  => 'Server error while building preview',
            'detail' => $e->getMessage(),
            'buffer' => $buffer ?: null,
        ], JSON_INVALID_UTF8_SUBSTITUTE);
    }
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8" />
    <title>Local Campaign Sender</title>
    <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 32px; }
        select, button, input[type=email], input[type=text], input[type=checkbox], label { font-size: 14px; }
        input[type=text], input[type=email] { padding: 6px 10px; }
        .grid { display: grid; gap: 12px; max-width: 920px; }
        .row { display: grid; gap: 8px; }
        .log { margin-top: 24px; white-space: pre-line; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f7f7f7; padding: 12px; border-radius: 6px; }
        iframe.preview { width: 100%; height: 560px; border: 1px solid #ddd; margin-top: 12px; background: white; }
        .warn { color: #b00020; font-weight: 600; }
        .ok { color: #0a7d27; font-weight: 600; }
        .hint { color: #666; font-size: 12px; }
        fieldset { border: 1px solid #ddd; padding: 12px; border-radius: 8px; }
        legend { padding: 0 6px; color: #444; }
        label.inline { display: inline-flex; align-items: center; gap: 6px; }
        ul.issues { margin: 6px 0 0 18px; padding: 0; }
        .banner { padding: 10px 12px; border-radius: 6px; margin-top: 12px; }
        .banner.ok { background: #eaf6ee; color: #0a7d27; }
        .banner.warn { background: #fde7ea; color: #b00020; }
    </style>
</head>
<body>
<h2>📨 Local Campaign Sender</h2>
<p class="hint">Local-only. Run with <code>php -S 127.0.0.1:8000</code>.</p>

<form method="POST" class="grid" id="sendForm">
    <fieldset>
        <legend>Campaign</legend>
        <div class="row">
            <label for="campaign">Template file (in /campaigns):</label>
            <select name="campaign" id="campaign" required>
                <option value="">-- Choose --</option>
                <?php foreach (getCampaignFiles($campaignDir) as $file): ?>
                    <option value="<?= htmlspecialchars($file) ?>"><?= htmlspecialchars($file) ?></option>
                <?php endforeach; ?>
            </select>
        </div>

        <div class="row">
            <label for="subject">Email subject:</label>
            <input type="text" name="subject" id="subject" placeholder="Check out our new menu!" value="Check out our new menu!" required style="width: 480px;">
            <span class="hint">The preview and checks reflect the subject.</span>
        </div>
    </fieldset>

    <fieldset>
        <legend>Recipients</legend>
        <div class="row">
            <label><input type="radio" name="recipientMode" value="TESTCUSTOMERS" required> Test Database</label>
            <label><input type="radio" name="recipientMode" value="CUSTOMERS" required> Real Customers (PROD)</label>
            <label><input type="radio" name="recipientMode" value="INDIVIDUAL" required> Individual Test Email</label>
        </div>
        <div class="row">
            <label for="testEmail">If sending individual, enter email:</label>
            <input type="email" name="testEmail" id="testEmail" placeholder="you@example.com" style="width: 320px;">
        </div>
        <div class="row">
            <label class="warn">If sending to real customers, type <strong>CONFIRM SEND</strong>:</label>
            <input type="text" name="confirmSend" placeholder="CONFIRM SEND" style="width: 320px;">
        </div>
    </fieldset>

    <fieldset>
        <legend>Send Options</legend>
        <div class="row">
            <label class="inline">
                <input type="checkbox" name="overrideLint" value="1">
                Override lint failures (allow send despite issues)
            </label>
        </div>
        <div class="row">
            <label class="inline">
                <input type="checkbox" name="sendSummary" value="1" checked>
                Email me a summary when done
            </label>
            <input type="email" name="summaryEmail" placeholder="summary@example.com" value="<?= htmlspecialchars($fromAddr) ?>" style="width: 320px;">
        </div>
    </fieldset>

    <div class="row">
        <button type="submit" name="action" value="send">Send to Selected</button>
    </div>
</form>

<!-- Consolidated Live Preview (subject-aware) + issues -->
<h3 style="margin-top:32px;">🔎 Preview</h3>
<div class="hint">The preview shows your selected template with CSS inlined and the standard unsubscribe appended (dummy token).</div>
<iframe class="preview" id="livePreview" title="Preview (inline CSS + unsubscribe)"></iframe>

<h3 style="margin-top:16px;">🧪 Template Issues</h3>
<div id="issuesPanel" class="log">
  <div id="issuesSummary" class="hint">No file selected yet.</div>
  <ul id="issuesList" class="issues"></ul>
</div>

<script>
  const select = document.getElementById('campaign');
  const subj   = document.getElementById('subject');
  const iframe = document.getElementById('livePreview');
  const issuesSummary = document.getElementById('issuesSummary');
  const issuesList = document.getElementById('issuesList');

  async function loadPreview() {
    const filename = select.value;
    const subject  = subj.value || '';
    if (!filename) {
      iframe.srcdoc = '<div style="padding:24px;color:#666;font-family:system-ui">Select a template to preview it here.</div>';
      issuesSummary.textContent = 'No file selected yet.';
      issuesList.innerHTML = '';
      return;
    }
    try {
      const res = await fetch(`send_emails.php?template_preview=${encodeURIComponent(filename)}&subject=${encodeURIComponent(subject)}`, {cache: 'no-store'});
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        throw new Error(`Preview endpoint did not return JSON. First chars: ${text.slice(0,120)}`);
      }

      if (!res.ok || data.error) {
        const msg = data?.error || `HTTP ${res.status}`;
        const detail = data?.detail ? ` — ${data.detail}` : '';
        const buf = data?.buffer ? `\nServer notes: ${data.buffer}` : '';
        throw new Error(`${msg}${detail}${buf}`);
      }

      iframe.srcdoc = data.html;

      // Show issues
      issuesList.innerHTML = '';
      const issues = data.issues || [];
      if (data.buffer) {
        issues.push({ severity: 'warn', msg: `Server notes: ${data.buffer}` });
      }
      if (issues.length) {
        const errors = issues.filter(i => i.severity === 'error');
        issuesSummary.innerHTML = (errors.length ? '<span class="warn">Blocking issues detected.</span> ' : '') +
                                  `Found ${issues.length} issue(s).`;
        issues.forEach(i => {
          const li = document.createElement('li');
          li.textContent = `${(i.severity || 'warn').toUpperCase()}: ${i.msg}`;
          if (i.severity === 'error') li.style.color = '#b00020';
          issuesList.appendChild(li);
        });
      } else {
        issuesSummary.innerHTML = '<span class="ok">No issues detected.</span>';
      }
    } catch (e) {
      iframe.srcdoc = `<div style="padding:24px;color:#b00020;font-family:system-ui">Error: ${e.message}</div>`;
      issuesSummary.textContent = 'Error loading preview.';
      issuesList.innerHTML = '';
    }
  }

  select.addEventListener('change', loadPreview);
  subj.addEventListener('input', () => { clearTimeout(window._subjT); window._subjT = setTimeout(loadPreview, 200); });
  loadPreview();
</script>

<?php
/* ==========================
   SEND WITH GATED LINT
   ========================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'send') {
    // Prevent premature timeouts if tab closes etc.
    ignore_user_abort(true);
    set_time_limit(0);

    $selectedFile  = basename($_POST['campaign'] ?? '');
    $subject       = trim($_POST['subject'] ?? '');
    // Subject hardening
    $subject = preg_replace('/[\r\n]+/', ' ', $subject);
    if (mb_strlen($subject) > 200) {
        $subject = mb_substr($subject, 0, 200) . '…';
    }

    $recipientMode = $_POST['recipientMode'] ?? '';
    $testEmail     = filter_var($_POST['testEmail'] ?? '', FILTER_VALIDATE_EMAIL);
    $confirmSend   = trim($_POST['confirmSend'] ?? '');
    $overrideLint  = isset($_POST['overrideLint']) && $_POST['overrideLint'] === '1';
    $sendSummary   = isset($_POST['sendSummary']) && $_POST['sendSummary'] === '1';
    $summaryEmail  = filter_var($_POST['summaryEmail'] ?? '', FILTER_VALIDATE_EMAIL) ?: null;

    $campaignPath  = "$campaignDir/$selectedFile";
    if (!$selectedFile || !is_file($campaignPath)) {
        echo "<div class='banner warn'>❌ Campaign file not found or not selected.</div>";
        exit;
    }
    $rawTemplate = file_get_contents($campaignPath);
    if ($rawTemplate === false) {
        echo "<div class='banner warn'>❌ Failed to read campaign file.</div>";
        exit;
    }

    // Build/validate recipient list
    $table = null;
    $individual = false;
    if ($recipientMode === 'INDIVIDUAL') {
        if (!$testEmail) {
            echo "<div class='banner warn'>❌ You must enter a valid email for individual mode.</div>";
            exit;
        }
        $individual = true;
    } else {
        if (!in_array($recipientMode, ['TESTCUSTOMERS', 'CUSTOMERS'], true)) {
            echo "<div class='banner warn'>❌ Invalid recipient mode.</div>";
            exit;
        }
        if ($recipientMode === 'CUSTOMERS' && strtoupper($confirmSend) !== 'CONFIRM SEND') {
            echo "<div class='banner warn'>❌ To send to PROD, type EXACTLY: CONFIRM SEND</div>";
            exit;
        }
        $table = $recipientMode;
    }

    // Global lint on the template (with dummy token & real subject)
    $globalIssues = [];
    $dummyUnsub = $unsubscribeBase . "/unsubscribe.php?token=" . str_repeat('A', 64);
    processTemplate($rawTemplate, $dummyUnsub, $subject, $globalIssues);

    $errors = array_filter($globalIssues, fn($i)=>($i['severity']??'warn')==='error');
    $warnings = array_filter($globalIssues, fn($i)=>($i['severity']??'warn')==='warn');

    if (($errors || $warnings) && !$overrideLint) {
        echo "<div class='log warn'><strong>❌ Sending blocked due to template issues.</strong>\n";
        foreach ($globalIssues as $i) {
            $sev = strtoupper($i['severity'] ?? 'WARN');
            echo "• {$sev}: " . htmlspecialchars($i['msg']) . "\n";
        }
        echo "Enable 'Override lint failures' to proceed anyway.</div>";
        exit;
    }

    // SMTP preflight
    try {
        $probe = buildMailer($smtpHost, $smtpUser, $smtpPass, $smtpPort, $smtpSecurity, $fromAddr, $fromName,
                             $dkimDomain, $dkimSelector, $dkimIdentity, $dkimKeyPath);
        $probe->smtpConnect();
        $probe->smtpClose();
    } catch (Exception $e) {
        echo "<div class='banner warn'>❌ SMTP preflight failed: ".htmlspecialchars($e->getMessage())."</div>";
        exit;
    }

    // Build a reusable mailer (keep-alive)
    $mail = buildMailer($smtpHost, $smtpUser, $smtpPass, $smtpPort, $smtpSecurity, $fromAddr, $fromName,
                        $dkimDomain, $dkimSelector, $dkimIdentity, $dkimKeyPath);
    $mail->SMTPKeepAlive = true;

    echo "<div class='log'><strong>Sending:</strong> ".htmlspecialchars($selectedFile)."\n<strong>Subject:</strong> ".htmlspecialchars($subject)."\n<strong>Mode:</strong> ".htmlspecialchars($recipientMode)."\n</div>";

    $success = 0; $failed = 0; $failList = [];
    $count = 0; $total = 0;

    if ($individual) {
        // One-off send
        $email = $testEmail;
        $token = bin2hex(random_bytes(32)); // dummy token for individual testing
        $unsubURL  = $unsubscribeBase . "/unsubscribe.php?token=$token";
        $issues = [];
        $finalHtml = processTemplate($rawTemplate, $unsubURL, $subject, $issues);

        try {
            $mail->clearAllRecipients();
            $mail->Subject = $subject;
            $mail->Body    = $finalHtml;
            $mail->addAddress($email);

            // Headers for deliverability
            $mail->addCustomHeader('List-ID', 'Casa del Pollo <mail.casadelpollo.com>');
            $mail->addCustomHeader('Precedence', 'bulk');
            $mail->addCustomHeader('List-Unsubscribe', '<'.$unsubURL.'>');
            $mail->addCustomHeader('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click');

            $mail->send();
            $success++; $total=1;
            echo "<div class='ok'>✅ Sent to ".htmlspecialchars($email)."</div>";
        } catch (Exception $e) {
            $failed++; $total=1;
            $msg = $e->getMessage();
            $failList[] = [$email, $msg];
            echo "<div class='warn'>❌ Failed for ".htmlspecialchars($email).": ".htmlspecialchars($msg)."</div>";
        }
    } else {
        // Stream recipients from DB
        try {
            $query = "SELECT EMAIL, FIRSTNAME, UNSUBSCRIBE_TOKEN FROM $table WHERE EMAIL IS NOT NULL AND IS_SUBSCRIBED = 1";
            $stmt = $pdo->query($query, PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            echo "<div class='banner warn'>❌ DB error: " . htmlspecialchars($e->getMessage()) . "</div>";
            $mail->smtpClose();
            exit;
        }

        while ($c = $stmt->fetch()) {
            $total++;
            $email = $c['EMAIL'];
            $token = $c['UNSUBSCRIBE_TOKEN'] ?? bin2hex(random_bytes(32));
            $unsubURL  = $unsubscribeBase . "/unsubscribe.php?token=$token";

            $finalHtml = processTemplate($rawTemplate, $unsubURL, $subject, $tmpIssues = []);

            try {
                $mail->clearAllRecipients();
                $mail->Subject = $subject;
                $mail->Body    = $finalHtml;
                $mail->addAddress($email);

                $mail->addCustomHeader('List-ID', 'Casa del Pollo <mail.casadelpollo.com>');
                $mail->addCustomHeader('Precedence', 'bulk');
                $mail->addCustomHeader('List-Unsubscribe', '<'.$unsubURL.'>');
                $mail->addCustomHeader('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click');

                $mail->send();
                $success++;
                echo "<div class='ok'>✅ Sent to ".htmlspecialchars($email)."</div>";
            } catch (Exception $e) {
                $failed++;
                $msg = $e->getMessage();
                $failList[] = [$email, $msg];
                echo "<div class='warn'>❌ Failed for ".htmlspecialchars($email).": ".htmlspecialchars($msg)."</div>";
            }

            $count++;
            if ($count % $batchSize === 0) {
                if ($count < 1_000_000) { // arbitrary guard to always show pause unless tiny set
                    echo "<div>⏸ Pausing for {$pauseSeconds}s…</div>";
                    @ob_flush(); @flush();
                    sleep($pauseSeconds);
                }
            }
        }
    }

    // Close SMTP socket
    if (isset($mail)) {
    $mail->smtpClose();   // safely closes if an SMTP connection is open
}


    // Sticky banner summary
    $hadErrors = $failed > 0;
    echo $hadErrors
      ? "<div class='banner warn'>Some messages failed — see details below.</div>"
      : "<div class='banner ok'>All messages sent successfully.</div>";

    // Summary on page
    echo "<div class='log'><strong>Summary:</strong>\n";
    echo "Total: $total\nSuccessful: $success\nFailed: $failed\n";
    if ($failed && $failList) {
        echo "Failures:\n";
        foreach ($failList as [$em, $why]) {
            echo "• ".htmlspecialchars($em).": ".htmlspecialchars($why)."\n";
        }

        // CSV download (data URL)
        $rows = [["email","error"]];
        foreach ($failList as [$em,$why]) { $rows[] = [$em, $why]; }
        $csv = '';
        foreach ($rows as $r) { $csv .= '"' . implode('","', array_map(fn($s)=>str_replace('"','""',$s), $r)) . '"' . "\n"; }
        $b64 = base64_encode($csv);
        echo "</div><div class='row'><a download='failures.csv' href='data:text/csv;base64,$b64'>Download failures.csv</a></div><div class='log'>";
    }
    echo "</div>";

    // Optional summary email
    if ($sendSummary && $summaryEmail) {
        try {
            $summaryBody = "<h2>Campaign Summary</h2>"
                         . "<p><strong>Template:</strong> ".htmlspecialchars($selectedFile)."</p>"
                         . "<p><strong>Subject:</strong> ".htmlspecialchars($subject)."</p>"
                         . "<p><strong>Mode:</strong> ".htmlspecialchars($recipientMode)."</p>"
                         . "<p><strong>Total:</strong> $total<br><strong>Successful:</strong> $success<br><strong>Failed:</strong> $failed</p>";

            if ($failed && $failList) {
                $summaryBody .= "<h3>Failures</h3><ul>";
                foreach ($failList as [$em, $why]) {
                    $summaryBody .= "<li>".htmlspecialchars($em)." — ".htmlspecialchars($why)."</li>";
                }
                $summaryBody .= "</ul>";
            }

            $reporter = buildMailer($smtpHost, $smtpUser, $smtpPass, $smtpPort, $smtpSecurity, $fromAddr, $fromName,
                                    $dkimDomain, $dkimSelector, $dkimIdentity, $dkimKeyPath);
            $reporter->Subject = "[Summary] ".$subject;
            $reporter->Body    = $summaryBody;
            $reporter->addAddress($summaryEmail);
            $reporter->send();
            echo "<div class='ok'>📧 Summary emailed to ".htmlspecialchars($summaryEmail)."</div>";
        } catch (Exception $e) {
            echo "<div class='warn'>⚠️ Failed to send summary email: ".htmlspecialchars($e->getMessage())."</div>";
        }
    }
}
?>
</body>
</html>
