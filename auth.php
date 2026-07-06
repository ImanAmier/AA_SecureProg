<?php
// auth.php - Staff Key Authentication System (SECURE)
declare(strict_types=1);
require_once 'db_config.php'; // Exposes $pdo (PDO instance, least-privilege DB user)

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed.');
}

if (!isset($_POST['auth_key']) || !isset($_POST['username'])) {
    http_response_code(400);
    exit('Missing credentials.');
}

$inputKey = (string) $_POST['auth_key'];
$username = (string) $_POST['username'];

// --- Fix for Flaw D: Bound Constraint Logic ---
// mb_strlen counts CODE POINTS, not bytes, closing the multi-byte bypass gap.
if (mb_strlen($inputKey, 'UTF-8') > 256) {
    http_response_code(400);
    exit('Invalid credential length.');
}

try {
    // Parameterized lookup - no string concatenation into SQL (defense in depth,
    // consistent with the search.php remediation).
    $stmt = $pdo->prepare(
        "SELECT auth_key_hash FROM staff_credentials WHERE username = :u LIMIT 1"
    );
    $stmt->execute(['u' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    // --- Fix for Flaw E: Obsolete Cryptographic Primitive ---
    // password_verify() performs a constant-time comparison against an
    // Argon2id hash (see 2.2.3), so timing side-channels are also mitigated.
    if ($row && password_verify($inputKey, $row['auth_key_hash'])) {
        echo "Access Granted.";

        // Optional: transparent rehash if cost parameters have since increased,
        // keeping stored hashes current without forcing a password reset.
        if (password_needs_rehash($row['auth_key_hash'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($inputKey, PASSWORD_ARGON2ID);
            $update = $pdo->prepare("UPDATE staff_credentials SET auth_key_hash = :h WHERE username = :u");
            $update->execute(['h' => $newHash, 'u' => $username]);
        }
    } else {
        // Deliberately generic message: do not reveal whether the username
        // or the key was the incorrect part (prevents user enumeration).
        http_response_code(401);
        echo "Access Denied.";
    }
} catch (PDOException $e) {
    error_log('auth.php DB error: ' . $e->getMessage());
    http_response_code(500);
    echo "An internal error occurred. Please try again later.";
}

// --- Provisioning note for schema.sql migration ---
// Existing MD5 hashes must be migrated. Since MD5 cannot be reversed into the
// original key, staff must reset their auth key once; the new hash is generated via:
//   $newHash = password_hash($plainAuthKey, PASSWORD_ARGON2ID);
// and stored in the (now longer, e.g. VARCHAR(255)) auth_key_hash column.