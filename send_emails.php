<?php
// ========================
// Simple Campaign Sender
// ========================

// ADVANCED: keep false to prevent sending when lint checks fail.
// Set to true (temporarily) if you decide to keep the feature.
// UI control is removed on purpose for safety.
define('ALLOW_OVERRIDE_LINT', false);

// --- Minimal config you may already have ---
$campaignDir = __DIR__; // where your test.html/test2.html live
$availableFiles = ['test.html', 'test2.html']; // list your allowed campaign files

// --- Utilities ---
function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

/**
 * Example: load recipients from your database.
 * Replace this with your real logic. Return an array of:
 *   [ ['email' => 'a@b.com', 'name' => 'Alice'], ... ]
 */
function loadRecipients($audienceKey) {
  // TODO: Replace with real DB query based on $audienceKey
  if ($audienceKey === 'test') {
    return [
      ['email' => 'you@example.com', 'name' => 'You (Test)'],
    ];
  }
  // Example: full list stub
  return [
    ['email' => 'customer1@example.com', 'name' => 'Customer One'],
    ['email' => 'customer2@example.com', 'name' => 'Customer Two'],
  ];
}

/**
 * Very light lint: ensure unsubscribe exists and links aren’t obviously broken.
 * Return ['ok' => bool, 'messages' => [string, ...]]
 */
function lintEmailHtml($html) {
  $messages = [];

  // Must contain the word "unsubscribe" or a link to unsubscribe.php
  if (!preg_match('/unsubscribe/i', $html)) {
    $messages[] = 'No “unsubscribe” found in the email body.';
  }

  // Very basic broken-link check (looks for href="")
  if (preg_match_all('/href=["\']([^"\']+)["\']/', $html, $m)) {
    foreach ($m[1] as $url) {
      if (stripos($url, 'http') === 0) {
        // Don’t actually fetch; just flag obvious placeholders
        if (strpos($url, 'example.com') !== false) {
          $messages[] = 'Link appears to be a placeholder: ' . $url;
        }
      }
    }
  }

  return [
    'ok' => empty($messages),
    'messages' => $messages
  ];
}

/**
 * Append unsubscribe block if missing (simple helper).
 * If you already have /mnt/data/unsubscribe.php logic, you can require it and call that.
 */
function ensureUnsubscribe($html) {
  if (preg_match('/unsubscribe/i', $html)) return $html;

  $block = "\n<hr style=\"margin:24px 0;border:0;border-top:1px solid #ddd;\">\n" .
           "<p style=\"font-size:12px;color:#666;\">Don't want these emails? " .
           "<a href=\"/unsubscribe.php\">Unsubscribe</a>.</p>\n";
  // Insert before </body> if present
  if (stripos($html, '</body>') !== false) {
    return preg_replace('/<\/body>/i', $block . '</body>', $html, 1);
  }
  return $html . $block;
}

/**
 * Send one email. Replace with your mailer (mail(), SMTP lib, etc.).
 * Return true on success or a string error message on failure.
 */
function sendOne($toEmail, $toName, $subject, $html) {
  // Example using mail() for local use. Customize for your environment.
  $headers  = "MIME-Version: 1.0\r\n";
  $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
  $headers .= "From: Restaurant <no-reply@your-restaurant.local>\r\n";

  $ok = @mail($toEmail, $subject, $html, $headers);
  if ($ok) return true;
  return "PHP mail() returned false (check local mail configuration).";
}

// --- Handle POST ---
$results = null;
$errorTop = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $fileKey   = $_POST['campaign_file'] ?? '';
  $audience  = $_POST['audience']      ?? 'test';
  $subject   = trim($_POST['subject'] ?? '');

  // Validate subject
  if ($subject === '') {
    $errorTop = 'Please enter an email subject.';
  }

  // Validate file selection
  if (!in_array($fileKey, $availableFiles, true)) {
    $errorTop = 'Please choose a valid campaign file.';
  }

  if (!$errorTop) {
    $path = $campaignDir . DIRECTORY_SEPARATOR . $fileKey;
    $rawHtml = @file_get_contents($path);
    if ($rawHtml === false) {
      $errorTop = 'Unable to load the selected campaign file.';
    } else {
      // Ensure unsubscribe present
      $emailHtml = ensureUnsubscribe($rawHtml);

      // Lint
      $lint = lintEmailHtml($emailHtml);
      $maySend = $lint['ok'] || ALLOW_OVERRIDE_LINT;

      if (!$maySend) {
        $errorTop = "Quality checks failed. Please fix the issues and try again.";
      }

      if (!$errorTop) {
        // Load recipients & send
        $recipients = loadRecipients($audience);
        $sentList = [];
        $skippedList = [];
        $errorList = [];

        foreach ($recipients as $r) {
          $email = trim($r['email'] ?? '');
          if ($email === '' || strpos($email, '@') === false) {
            $skippedList[] = ['email' => $email ?: '(blank)', 'reason' => 'Invalid email address'];
            continue;
          }
          $res = sendOne($email, $r['name'] ?? '', $subject, $emailHtml);
          if ($res === true) {
            $sentList[] = ['email' => $email, 'name' => $r['name'] ?? ''];
          } else {
            $errorList[] = ['email' => $email, 'error' => is_string($res) ? $res : 'Unknown error'];
          }
        }

        $results = [
          'lint'    => $lint,
          'sent'    => $sentList,
          'skipped' => $skippedList,
          'errors'  => $errorList,
          'subject' => $subject,
          'file'    => $fileKey,
          'audience'=> $audience
        ];
      }
    }
  }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Send Restaurant Email Campaign</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; line-height: 1.4; }
    .card { max-width: 800px; border: 1px solid #ddd; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
    .field { margin: 14px 0; }
    input[type="text"], select { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 8px; }
    button { padding: 10px 16px; border: 0; border-radius: 8px; background: #2d6cdf; color: #fff; cursor: pointer; }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .error { background: #fdecea; border: 1px solid #f5c6cb; color: #a71d2a; padding: 10px; border-radius: 8px; }
    .hint { color: #555; font-size: 14px; }
    .results details { margin: 10px 0; }
    .preview { border: 1px solid #eee; padding: 12px; border-radius: 8px; max-height: 240px; overflow: auto; background: #fafafa; }
    .lint-warn { background: #fff8e1; border: 1px solid #ffe082; color: #6d4c41; padding: 10px; border-radius: 8px; margin-top: 10px; }
  </style>
</head>
<body>

  <h1>Send Restaurant Email Campaign</h1>
  <p class="hint">Choose your email design, confirm your audience, write the subject (at the bottom), and click Send. Results will appear on this page.</p>

  <?php if (!empty($errorTop)): ?>
    <div class="card error"><strong>Problem:</strong> <?= h($errorTop); ?></div>
  <?php endif; ?>

  <form method="post" class="card">
    <div class="field">
      <label for="campaign_file"><strong>1) Choose your email design</strong></label>
      <select id="campaign_file" name="campaign_file" required>
        <option value="">-- Select a file --</option>
        <?php foreach ($availableFiles as $f): ?>
          <option value="<?= h($f); ?>" <?= isset($_POST['campaign_file']) && $_POST['campaign_file'] === $f ? 'selected' : '' ?>>
            <?= h($f); ?>
          </option>
        <?php endforeach; ?>
      </select>
      <small class="hint">Pick the HTML file you want to send (for example, “test.html”).</small>
    </div>

    <div class="field">
      <label for="audience"><strong>2) Choose who should receive this</strong></label>
      <select id="audience" name="audience" required>
        <option value="test" <?= (($_POST['audience'] ?? '') === 'test') ? 'selected' : '' ?>>Test (send to me)</option>
        <option value="all"  <?= (($_POST['audience'] ?? '') === 'all')  ? 'selected' : '' ?>>All customers</option>
      </select>
      <small class="hint">Use “Test” first to preview in your inbox.</small>
    </div>

    <?php
    // Show a tiny preview of the selected file
    if (!empty($_POST['campaign_file']) && in_array($_POST['campaign_file'], $availableFiles, true)) {
      $pv = @file_get_contents($campaignDir . DIRECTORY_SEPARATOR . $_POST['campaign_file']);
      if ($pv !== false) {
        $pv = ensureUnsubscribe($pv);
        echo '<div class="field"><label><strong>Preview</strong></label><div class="preview">'. $pv .'</div></div>';
      }
    }
    ?>

    <!-- 3) Email Subject (moved to bottom) -->
    <div class="field">
      <label for="subject"><strong>3) Email Subject</strong></label>
      <input type="text" id="subject" name="subject" required
             placeholder="e.g., 20% Off This Weekend Only"
             value="<?= h($_POST['subject'] ?? ''); ?>" />
      <small class="hint">This is what your customers see in their inbox.</small>
    </div>

    <div class="field">
      <button type="submit">Send Emails</button>
    </div>

    <?php if (!empty($results['lint'])): ?>
      <?php if (!$results['lint']['ok']): ?>
        <div class="lint-warn">
          <strong>Quality Checks:</strong>
          <ul>
            <?php foreach ($results['lint']['messages'] as $m): ?>
              <li><?= h($m); ?></li>
            <?php endforeach; ?>
          </ul>
          <em>Fix these issues in your HTML and try again. (Override is disabled for safety.)</em>
        </div>
      <?php endif; ?>
    <?php endif; ?>
  </form>

  <?php if ($results): ?>
    <div class="card results">
      <h2>Send Results</h2>
      <p>
        <strong>Subject:</strong> <?= h($results['subject']); ?> <br>
        <strong>Design:</strong> <?= h($results['file']); ?> <br>
        <strong>Audience:</strong> <?= h($results['audience']); ?>
      </p>
      <p><strong>Sent:</strong> <?= count($results['sent']); ?> |
         <strong>Skipped:</strong> <?= count($results['skipped']); ?> |
         <strong>Errors:</strong> <?= count($results['errors']); ?></p>

      <?php if (!empty($results['sent'])): ?>
        <details open>
          <summary><strong>Delivered (<?= count($results['sent']); ?>)</strong></summary>
          <ul>
            <?php foreach ($results['sent'] as $r): ?>
              <li><?= h($r['email']); ?><?= isset($r['name']) && $r['name'] !== '' ? ' — ' . h($r['name']) : ''; ?></li>
            <?php endforeach; ?>
          </ul>
        </details>
      <?php endif; ?>

      <?php if (!empty($results['skipped'])): ?>
        <details>
          <summary><strong>Skipped (<?= count($results['skipped']); ?>)</strong></summary>
          <ul>
            <?php foreach ($results['skipped'] as $r): ?>
              <li><?= h($r['email']); ?> — <?= h($r['reason']); ?></li>
            <?php endforeach; ?>
          </ul>
        </details>
      <?php endif; ?>

      <?php if (!empty($results['errors'])): ?>
        <details>
          <summary><strong>Errors (<?= count($results['errors']); ?>)</strong></summary>
          <ul>
            <?php foreach ($results['errors'] as $r): ?>
              <li><?= h($r['email']); ?> — <?= h($r['error']); ?></li>
            <?php endforeach; ?>
          </ul>
        </details>
      <?php endif; ?>
    </div>
  <?php endif; ?>

  <div class="card">
    <h3>Quick Tips</h3>
    <ul>
      <li>Always run a <strong>Test</strong> send to yourself first.</li>
      <li>Make sure there’s an <strong>Unsubscribe</strong> link in the email—this page adds one if missing.</li>
      <li>If you see quality warnings, fix your HTML file and try again.</li>
    </ul>
  </div>

</body>
</html>
