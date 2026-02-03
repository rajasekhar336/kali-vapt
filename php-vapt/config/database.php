<?php
// Database Configuration for Finding Focus VAPT
// PHP + PostgreSQL Implementation

class Database {
    private $host = 'localhost';
    private $port = '5432';
    private $dbname = 'vapt_platform';
    private $user = 'vapt_user';
    private $password = 'vapt_secure_password';
    
    private $connection;
    
    public function __construct() {
        $this->connect();
    }
    
    private function connect() {
        try {
            $dsn = "pgsql:host={$this->host};port={$this->port};dbname={$this->dbname};";
            $this->connection = new PDO($dsn, $this->user, $this->password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            die("Database connection failed: " . $e->getMessage());
        }
    }
    
    public function getConnection() {
        return $this->connection;
    }
    
    public function query($sql, $params = []) {
        try {
            $stmt = $this->connection->prepare($sql);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            die("Query failed: " . $e->getMessage());
        }
    }
    
    public function fetch($sql, $params = []) {
        $stmt = $this->query($sql, $params);
        return $stmt->fetch();
    }
    
    public function fetchAll($sql, $params = []) {
        $stmt = $this->query($sql, $params);
        return $stmt->fetchAll();
    }
    
    public function insert($table, $data) {
        $columns = implode(', ', array_keys($data));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        $values = array_values($data);
        
        $sql = "INSERT INTO {$table} ({$columns}) VALUES ({$placeholders}) RETURNING id";
        $stmt = $this->query($sql, $values);
        return $stmt->fetchColumn();
    }
    
    public function update($table, $data, $where, $whereParams = []) {
        $setClause = [];
        $values = [];
        
        foreach ($data as $column => $value) {
            $setClause[] = "{$column} = ?";
            $values[] = $value;
        }
        
        $setClause = implode(', ', $setClause);
        $values = array_merge($values, $whereParams);
        
        $sql = "UPDATE {$table} SET {$setClause} WHERE {$where}";
        return $this->query($sql, $values);
    }
    
    public function delete($table, $where, $params = []) {
        $sql = "DELETE FROM {$table} WHERE {$where}";
        return $this->query($sql, $params);
    }
    
    public function lastInsertId() {
        return $this->connection->lastInsertId();
    }
    
    public function beginTransaction() {
        return $this->connection->beginTransaction();
    }
    
    public function commit() {
        return $this->connection->commit();
    }
    
    public function rollback() {
        return $this->connection->rollback();
    }
}

// Global database instance
$db = new Database();
