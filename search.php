<?php
// search.php - Patient & Medical Record Search Proxy (SECURE)
declare(strict_types=1);
require_once 'db_config.php'; // Must expose a PDO instance named $pdo, least-privilege DB user

// --- Input Validation Boundary ---
// Reject the request outright if the expected parameter is missing or not a string.
if (!isset($_GET['keyword']) || !is_string($_GET['keyword'])) {
    http_response_code(400);
    echo "Invalid request: 'keyword' parameter is required.";
    exit;
}

$keyword = trim($_GET['keyword']);

// Optional defense-in-depth: constrain length to a sane search-term size.
// This is a UX/DoS control, NOT the injection defense (PDO binding is).
if (mb_strlen($keyword, 'UTF-8') > 100) {
    http_response_code(400);
    echo "Search term too long.";
    exit;
}

try {
    // --- Fix for Flaw A: SQL Injection ---
    // Data plane (keyword) and command plane (SQL grammar) are now transmitted
    // as separate channels. The placeholder is bound, never concatenated.
    $stmt = $pdo->prepare(
        "SELECT id, name, illness_history FROM patient_records WHERE name LIKE :kw"
    );
    $stmt->execute(['kw' => '%' . $keyword . '%']);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (count($rows) > 0) {
        foreach ($rows as $row) {
            // --- Fix for Flaws B & C: Reflected XSS ---
            // Every value that originated from user input OR from the database
            // (defense in depth: stored data could itself have been poisoned)
            // is passed through context-aware output encoding before being
            // placed into the HTML response stream.
            echo "<div>Result found for keyword: "
                . htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8')
                . "<br>";
            echo "Patient: " . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8')
                . " | History: " . htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8')
                . "</div><hr>";
        }
    } else {
        echo "No records found for: " . htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');
    }
} catch (PDOException $e) {
    // Never leak raw exception detail (schema names, query text) to the client.
    error_log('search.php DB error: ' . $e->getMessage());
    http_response_code(500);
    echo "An internal error occurred. Please try again later.";
}