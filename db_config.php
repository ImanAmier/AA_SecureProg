<?php
// db_config.php - shared PDO connection for search.php and auth.php

$host = 'localhost';
$db   = 'medic_vault_db';
$user = 'root';      // adjust if your MySQL user differs
$pass = '';           // adjust if your MySQL root password isn't empty

$dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4";

try {
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false, // real prepared statements, not emulated
    ]);
} catch (PDOException $e) {
    error_log('DB connection failed: ' . $e->getMessage());
    http_response_code(500);
    exit('Database connection error.');
}