<?php
// Login Handler for Finding Focus VAPT
// PHP + PostgreSQL Implementation

require_once '../config/database.php';
require_once '../src/utils/auth.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($email) || empty($password)) {
        $error = 'Please enter both email and password';
    } else {
        if ($auth->login($email, $password)) {
            header('Location: dashboard.php');
            exit;
        } else {
            $error = 'Invalid email or password';
        }
    }
}

// Include the login view
include '../views/login.php';
?>
