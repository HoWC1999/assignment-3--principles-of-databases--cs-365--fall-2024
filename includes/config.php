<?php
// php/config.php

// Database credentials
$dsn = 'mysql:host=localhost;dbname=student_passwords';
$username = 'passwords_user';
$password = ''; // No password as per the requirements

try {
    // Create a PDO instance
    $db = new PDO($dsn, $username, $password);
    // Set error mode to exceptions
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    // Set default fetch mode
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    // Set character set
    $db->exec("SET NAMES utf8");
} catch (PDOException $e) {
    // Display error message
    echo "Error: " . $e->getMessage();
    die();
}
define('ENCRYPTION_KEY', 'SuperSecretKey123!'); // Replace with your actual key
define('ENCRYPTION_IV', '00112233445566778899AABBCCDDEEFF'); // Replace with your actual IV
?>
