-- mysql/setup.sql

-- Create the 'student_passwords' database
CREATE DATABASE IF NOT EXISTS student_passwords;
USE student_passwords;

-- Create the 'passwords_user' user without a password
CREATE USER IF NOT EXISTS 'passwords_user'@'localhost' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON student_passwords.* TO 'passwords_user'@'localhost';

-- Set the block encryption mode to AES-256-CBC
SET block_encryption_mode = 'aes-256-cbc';

-- Set the encryption key by using a securely hashed passphrase 'SuperSecretKey123!' with SHA-256
SET @key_str = UNHEX(SHA2('SuperSecretKey123!', 256));

-- Set a fixed initialization vector (IV)
SET @fixed_iv = UNHEX('00112233445566778899AABBCCDDEEFF');

-- Create the 'users' table
DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(64) NOT NULL,
  last_name VARCHAR(64) NOT NULL,
  email VARCHAR(256) NOT NULL
);

-- Create the 'websites' table
DROP TABLE IF EXISTS websites;
CREATE TABLE IF NOT EXISTS websites (
  website_id INT AUTO_INCREMENT PRIMARY KEY,
  website_name VARCHAR(512) NOT NULL,
  website_url VARCHAR(512) NOT NULL UNIQUE
);

-- Create the 'registers_for' table
DROP TABLE IF EXISTS registers_for;
CREATE TABLE IF NOT EXISTS registers_for (
  account_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  website_id INT NOT NULL,
  username VARCHAR(64) NOT NULL,
  password VARBINARY(512) NOT NULL,
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(user_id),
  FOREIGN KEY (website_id) REFERENCES websites(website_id)
);

-- Insert initial user data
INSERT INTO users (first_name, last_name, email)
VALUES ('Andrew', 'Fletcher', 'afletcher@hartford.edu')
ON DUPLICATE KEY UPDATE user_id = LAST_INSERT_ID(user_id);

-- Insert initial website data
INSERT INTO websites (website_name, website_url)
VALUES
  ('MySQL', 'http://mysql.com'),
  ('Google', 'https://google.com'),
  ('LinkedIn', 'https://linkedin.com'),
  ('Facebook', 'http://facebook.com'),
  ('Twitter', 'http://twitter.com'),
  ('University of Hartford', 'http://hartford.edu'),
  ('GitHub', 'http://github.com'),
  ('Amazon', 'http://amazon.com'),
  ('Netflix', 'http://netflix.com'),
  ('Instagram', 'http://instagram.com')
ON DUPLICATE KEY UPDATE website_id = LAST_INSERT_ID(website_id);

-- Retrieve the user_id for 'Andrew Fletcher'
SET @user_id = (SELECT user_id FROM users WHERE email = 'afletcher@hartford.edu');

-- Insert initial account data
INSERT INTO registers_for (user_id, website_id, username, password, comment, created_at)
VALUES
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://mysql.com'),
    'andrew.flet',
    AES_ENCRYPT('MySQL!StrongP@ssw0rd', @key_str, @fixed_iv),
    'Database management',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'https://google.com'),
    'andrew.flet84',
    AES_ENCRYPT('G0ogleAccount$2023', @key_str, @fixed_iv),
    'Gmail account',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'https://linkedin.com'),
    'afletcher.pro',
    AES_ENCRYPT('Linkedin#JobSeek3r', @key_str, @fixed_iv),
    'Professional network',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://facebook.com'),
    'andyf',
    AES_ENCRYPT('Fb_Secure!2021', @key_str, @fixed_iv),
    'Social media',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://twitter.com'),
    'fletch_andrew',
    AES_ENCRYPT('Tw!tter@Handle987', @key_str, @fixed_iv),
    'Social media',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://hartford.edu'),
    'a.fletcher',
    AES_ENCRYPT('University#Hart123', @key_str, @fixed_iv),
    'University account',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://github.com'),
    'andrew-code',
    AES_ENCRYPT('GitHub_Coder!2022', @key_str, @fixed_iv),
    'Code repository',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://amazon.com'),
    'a.flet.amazon',
    AES_ENCRYPT('Am@zonShopper*789', @key_str, @fixed_iv),
    'Shopping account',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://netflix.com'),
    'afletcher.nfx',
    AES_ENCRYPT('N3tflixP@ssword2021', @key_str, @fixed_iv),
    'Streaming service',
    CURRENT_TIMESTAMP
  ),
  (
    @user_id,
    (SELECT website_id FROM websites WHERE website_url = 'http://instagram.com'),
    'drew.insta84',
    AES_ENCRYPT('Insta_Glam!42', @key_str, @fixed_iv),
    'Social media',
    CURRENT_TIMESTAMP
  );
