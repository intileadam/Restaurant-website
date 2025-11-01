<?php
// ========================
// Simple Campaign Sender
// ========================

// ADVANCED: keep false to prevent sending when lint checks fail.
// Set to true (temporarily) if you decide to keep the feature.
// UI control is removed on purpose for safety.
define('ALLOW_OVERRIDE_LINT', false);

// --- Minimal config you may already have ---
$campaignDir = __DIR__ . '/campaigns';
$availableFiles = array_values(array_filter(scandir($campaignDir), function($f) use ($campaignDir) {
    return is_file($campaignDir . DIRECTORY_SEPARATOR . $f) && preg_match('/\.html$/i', $f);
}));
// --- Utilities ---
function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

/**
 * Example: load recipients from your database.
 * Replace this with your real logic. Return an array of:
 *   [ ['email' => 'a@b.com', 'name' => 'Alice'], ... ]
 */
function loadRecipients($audienceKey) {
  // TODO: Replace with real DB query based on $audienceKey
  // Example stubs:
  if ($audienceKey === 'test') {
    return [['email' => 'you@example.com', 'name' => 'You (Test)']];
  }
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
  $testEmail = trim($_POST['test_email'] ?? '');

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
        if ($audience === 'test') {
          $recipients = [];
          if ($testEmail !== '' && strpos($testEmail, '@') !== false) {
            $recipients[] = ['email' => $testEmail, 'name' => 'Test Recipient'];
          } else {
            $recipients[] = ['email' => 'you@example.com', 'name' => 'You (Test)'];
          }
        } else {
          $recipients = loadRecipients($audience);
        }

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
          'audience'=> $audience,
          'test_email' => $testEmail
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
    .card { max-width: 900px; border: 1px solid #ddd; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
    .field { margin: 14px 0; }
    input[type="text"], input[type="email"], select { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 8px; }
    button { padding: 10px 16px; border: 0; border-radius: 8px; background: #2d6cdf; color: #fff; cursor: pointer; }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .error { background: #fdecea; border: 1px solid #f5c6cb; color: #a71d2a; padding: 10px; border-radius: 8px; }
    .hint { color: #555; font-size: 14px; }
    .results details { margin: 10px 0; }
    .preview { width: 100%; height: 260px; border: 1px solid #eee; border-radius: 8px; background: #fff; }
    .lint-warn { background: #fff8e1; border: 1px solid #ffe082; color: #6d4c41; padding: 10px; border-radius: 8px; margin-top: 10px; }
  </style>
</head>
<body>

  <h1>Send Restaurant Email Campaign</h1>
  <p class="hint">Choose your email design, confirm your audience, write the subject (at the bottom), and click Send. Results will appear on this page.</p>

  <?php if (!empty($errorTop)): ?>
    <div class="card error"><strong>Problem:</strong> <?= h($errorTop); ?></div>
  <?php endif; ?>

  <form method="post" class="card" id="sendForm">
    <div class="field">
    <label for="campaign_file"><strong>1) Choose your html file</strong></label>
    <select id="campaign_file" name="campaign_file" onchange="window._updatePreview()" required>
        <!-- your PHP options -->
    </select>
    <small class="hint">Pick the HTML file (e.g., “test.html”).</small>
    </div>

    <div class="field">
    <label><strong>Preview</strong></label>
    <iframe id="previewFrame" class="preview" title="Email Preview"
            style="width:100%;height:260px;border:1px solid #eee;border-radius:8px;background:#fff;"></iframe>
    <small class="hint">Shows the selected file. During send, an unsubscribe link is auto-added if missing.</small>
    </div>

    <script>
  // Define globally so inline onchange can call it even if an early error occurs
  window._updatePreview = async function() {
    const fileSel = document.getElementById('campaign_file');
    const frame   = document.getElementById('previewFrame');
    if (!fileSel || !frame) {
      console.error('Preview init: missing #campaign_file or #previewFrame');
      return;
    }

    const file = (fileSel.value || '').trim();
    if (!file) {
      frame.srcdoc = "<p style='padding:12px;color:#666;'>No file selected.</p>";
      return;
    }

    const url = "/campaigns/" + encodeURIComponent(file); // absolute path

    try {
      frame.srcdoc = "<p style='padding:12px;color:#666;'>Loading preview…</p>";
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const html = await res.text();
      frame.srcdoc = html;
    } catch (e) {
      frame.srcdoc =
        "<pre style='padding:12px;white-space:pre-wrap;color:#a71d2a;'>Preview fetch failed: "
        + (e && e.message ? e.message : String(e)) + "</pre>";
    }
  };

  // Also attach an event listener (redundant with inline onchange, but helpful)
  (function() {
    const fileSel = document.getElementById('campaign_file');
    if (fileSel) fileSel.addEventListener('change', window._updatePreview);
    // Show immediately if a value is already selected (e.g., after POST)
    if (fileSel && fileSel.value) window._updatePreview();
  })();
</script>



    <!-- Live Preview -->
    <div class="field">
      <label><strong>Preview</strong></label>
      <iframe id="previewFrame" class="preview" title="Email Preview"></iframe>
      <small class="hint">Preview shows the file content. During send, an unsubscribe link is automatically added if missing.</small>
    </div>

    <div class="field">
      <label for="audience"><strong>2) Choose who should receive this</strong></label>
      <select id="audience" name="audience" required>
        <option value="test" <?= (($_POST['audience'] ?? '') === 'test') ? 'selected' : '' ?>>Test (send to me)</option>
        <option value="all"  <?= (($_POST['audience'] ?? '') === 'all')  ? 'selected' : '' ?>>All customers</option>
      </select>
      <small class="hint">Use “Test” first to preview in your inbox.</small>
    </div>

    <!-- Test destination email (visible only in Test mode) -->
    <div class="field" id="testEmailRow" style="display:none;">
      <label for="test_email"><strong>Test destination email</strong></label>
      <input type="email" id="test_email" name="test_email" placeholder="name@example.com"
             value="<?= h($_POST['test_email'] ?? ''); ?>" />
      <small class="hint">Only used when “Test” is selected.</small>
    </div>

    <!-- 3) Email Subject (at bottom) -->
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
        <strong>Audience:</strong> <?= h($results['audience']); ?><?= $results['audience'] === 'test' && !empty($results['test_email']) ? ' (to ' . h($results['test_email']) . ')' : ''; ?>
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

<script>
  // Live Preview
  document.addEventListener('DOMContentLoaded', function() {
  const fileSel = document.getElementById('campaign_file');
  const frame   = document.getElementById('previewFrame');

  // Define globally so we can also call from the select's onchange as a fallback
  window._updatePreview = async function _updatePreview() {
    if (!fileSel || !frame) return; // IDs missing
    const file = (fileSel.value || "").trim();
    if (!file) {
      frame.srcdoc = "<p style='padding:12px;color:#666;'>No file selected.</p>";
      return;
    }
    // Use absolute path to avoid any relative URL quirks
    const url = "/campaigns/" + encodeURIComponent(file);
    try {
      // Helpful visual while loading
      frame.srcdoc = "<p style='padding:12px;color:#666;'>Loading preview…</p>";
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const html = await res.text();
      frame.srcdoc = html;
      // console.log("Preview loaded:", url); // uncomment for debugging
    } catch (e) {
      frame.srcdoc = "<pre style='padding:12px;white-space:pre-wrap;color:#a71d2a;'>Preview fetch failed: "
        + (e && e.message ? e.message : String(e)) + "</pre>";
    }
  };

  // Attach listener if elements exist
  if (fileSel && frame) {
    fileSel.addEventListener('change', window._updatePreview);
    // Also fire once on load, in case a value is preselected
    if (fileSel.value) window._updatePreview();
  }
});

  // Confirm production / all-customers sends
  (function() {
    const form = document.getElementById('sendForm');
    const audience = document.getElementById('audience');
    form.addEventListener('submit', function(ev) {
      if (audience.value === 'all') {
        const ok = window.confirm("You are about to send to ALL customers (production). Continue?");
        if (!ok) ev.preventDefault();
      }
    });
  })();
</script>

</body>
</html>
