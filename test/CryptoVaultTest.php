<?php
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../crypto_vault.php';

final class CryptoVaultTest extends TestCase
{
    private string $testKey;

    protected function setUp(): void
    {
        $this->testKey = random_bytes(32);
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $plaintext = 'DIAGNOSIS: Stage-2 Carcinoma. STATUS: Critical.';
        $encrypted = vaultEncrypt($plaintext, $this->testKey);
        $decrypted = vaultDecrypt($encrypted, $this->testKey);
        $this->assertSame($plaintext, $decrypted);
    }

    public function testTamperedCiphertextThrowsIntegrityException(): void
    {
        $plaintext = 'DIAGNOSIS: Acute Type-2 Diabetes.';
        $encrypted = vaultEncrypt($plaintext, $this->testKey);

        $raw = base64_decode($encrypted);
        $lastIndex = strlen($raw) - 1;
        $raw[$lastIndex] = chr(ord($raw[$lastIndex]) ^ 0xFF);
        $tampered = base64_encode($raw);

        $this->expectException(CryptographicIntegrityException::class);
        vaultDecrypt($tampered, $this->testKey);
    }

    public function testWrongKeyThrowsIntegrityException(): void
    {
        $plaintext = 'DIAGNOSIS: Managed.';
        $encrypted = vaultEncrypt($plaintext, $this->testKey);
        $wrongKey = random_bytes(32);

        $this->expectException(CryptographicIntegrityException::class);
        vaultDecrypt($encrypted, $wrongKey);
    }

    public function testPasswordHashVerifyMatches(): void
    {
        $plainKey = 'doctorsecret';
        $hash = password_hash($plainKey, PASSWORD_ARGON2ID);

        $this->assertTrue(password_verify($plainKey, $hash));
        $this->assertFalse(password_verify('wrongkey', $hash));
    }
}