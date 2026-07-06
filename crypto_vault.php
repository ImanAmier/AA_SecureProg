<?php
// crypto_vault.php - Patient Medical Records Symmetric Protection (SECURE)
declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php'; // for vlucas/phpdotenv
require_once __DIR__ . '/CryptographicIntegrityException.php';

use Dotenv\Dotenv;

// --- Fix for Flaw G: Cryptographic Key Hardcoding ---
// Secret is loaded from an externalized, gitignored .env file, never from source.
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

$rawKey = $_ENV['VAULT_ENCRYPTION_KEY'] ?? null;
if (!$rawKey || strlen(base64_decode($rawKey, true) ?: '') !== 32) {
    // Fail loudly at startup rather than silently encrypting with a bad key.
    throw new RuntimeException('VAULT_ENCRYPTION_KEY missing or not a valid 32-byte base64 key.');
}
$key = base64_decode($rawKey);

const IV_LENGTH  = 12; // bytes, per NIST SP 800-38D recommendation for GCM
const TAG_LENGTH = 16; // bytes, full-length GCM authentication tag

/**
 * Encrypts a plaintext string using AES-256-GCM and packs IV + tag + ciphertext
 * into a single Base64-encoded transportable string.
 */
function vaultEncrypt(string $plaintext, string $key): string
{
    // --- Fix for Flaw F: fresh CSPRNG-sourced IV per call, never reused ---
    $iv = random_bytes(IV_LENGTH);
    $tag = '';

    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',          // Associated Data (AAD) - none used here, but supported
        TAG_LENGTH
    );

    if ($ciphertext === false) {
        throw new RuntimeException('Encryption failed.');
    }

    // Fixed-length prefix packing: [IV][TAG][CIPHERTEXT]
    $payload = $iv . $tag . $ciphertext;

    return base64_encode($payload);
}

/**
 * Reverses vaultEncrypt(): unpacks IV, tag, and ciphertext by fixed offset,
 * then verifies authenticity during decryption.
 *
 * @throws CryptographicIntegrityException if the tag does not match (tampering).
 */
function vaultDecrypt(string $encodedPayload, string $key): string
{
    $raw = base64_decode($encodedPayload, true);
    if ($raw === false || strlen($raw) < IV_LENGTH + TAG_LENGTH) {
        throw new CryptographicIntegrityException('Malformed vault payload.');
    }

    // Deterministic fixed-offset unpacking - safe because IV/TAG lengths are constants.
    $iv         = substr($raw, 0, IV_LENGTH);
    $tag        = substr($raw, IV_LENGTH, TAG_LENGTH);
    $ciphertext = substr($raw, IV_LENGTH + TAG_LENGTH);

    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    // --- Fix for silent-failure runtime trap (3.1.4) ---
    // Explicitly detect tag-mismatch/failure and convert it into a typed,
    // catchable exception instead of letting `false` propagate silently.
    if ($plaintext === false) {
        throw new CryptographicIntegrityException(
            'Authentication tag verification failed: payload may have been tampered with.'
        );
    }

    return $plaintext;
}

// --- HTTP entry point ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    if (!isset($_POST['payload'])) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Missing payload.']);
        exit;
    }

    try {
        $encrypted = vaultEncrypt((string) $_POST['payload'], $key);
        echo json_encode(['status' => 'vaulted', 'data' => $encrypted]);
    } catch (Throwable $e) {
        error_log('crypto_vault.php error: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Encryption failed.']);
    }
}