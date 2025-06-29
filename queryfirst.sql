-- Create database
CREATE DATABASE IF NOT EXISTS flaskappdb;
USE flaskappdb;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    role VARCHAT(100) NOT NULL DEFAULT 'user',
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO users (name, email, password) VALUES 
(
    'John Doe', 
    'john.doe@example.com', 
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeVMUvfJjP1.R.8PS'
),
(
    'Jane Smith', 
    'jane.smith@example.com', 
    '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p4TNiuRS.F9z8BLcEqz.7.6q'
);

-- Verify the data
SELECT * FROM users;

-- Show table structure
DESCRIBE users;
