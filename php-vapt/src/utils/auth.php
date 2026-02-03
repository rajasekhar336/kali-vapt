<?php
// Authentication System for Finding Focus VAPT
// PHP + PostgreSQL Implementation

session_start();

class Auth {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function login($email, $password) {
        $sql = "SELECT * FROM users WHERE email = ? AND is_active = true";
        $user = $this->db->fetch($sql, [$email]);
        
        if ($user && password_verify($password, $user['password_hash'])) {
            // Update last login
            $this->db->update('users', 
                ['last_login' => date('Y-m-d H:i:s')], 
                'id = ?', 
                [$user['id']]
            );
            
            // Set session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];
            $_SESSION['logged_in'] = true;
            
            return true;
        }
        
        return false;
    }
    
    public function logout() {
        session_destroy();
        header('Location: login.php');
        exit;
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }
    
    public function requireLogin() {
        if (!$this->isLoggedIn()) {
            header('Location: login.php');
            exit;
        }
    }
    
    public function requireRole($role) {
        $this->requireLogin();
        if ($_SESSION['role'] !== $role && $_SESSION['role'] !== 'admin') {
            header('Location: unauthorized.php');
            exit;
        }
    }
    
    public function getCurrentUser() {
        if ($this->isLoggedIn()) {
            return [
                'id' => $_SESSION['user_id'],
                'username' => $_SESSION['username'],
                'email' => $_SESSION['email'],
                'full_name' => $_SESSION['full_name'],
                'role' => $_SESSION['role']
            ];
        }
        return null;
    }
    
    public function createUser($username, $email, $password, $full_name, $role = 'user') {
        // Check if user already exists
        $sql = "SELECT id FROM users WHERE username = ? OR email = ?";
        $existing = $this->db->fetch($sql, [$username, $email]);
        
        if ($existing) {
            return false;
        }
        
        // Create new user
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
        $userData = [
            'username' => $username,
            'email' => $email,
            'password_hash' => $passwordHash,
            'full_name' => $full_name,
            'role' => $role
        ];
        
        return $this->db->insert('users', $userData);
    }
    
    public function updatePassword($userId, $newPassword) {
        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        return $this->db->update('users', 
            ['password_hash' => $passwordHash], 
            'id = ?', 
            [$userId]
        );
    }
}

// Initialize auth system
$auth = new Auth($db);
