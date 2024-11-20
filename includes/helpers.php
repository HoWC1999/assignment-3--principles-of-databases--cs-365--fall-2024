<?php

function searchEntries($query)
{
    global $db;
    // Ensure the encryption mode is set correctly
    $db->exec("SET block_encryption_mode = 'aes-256-cbc'");
    $likeQuery = '%' . $query . '%';

    try {
        $stmt = $db->prepare("
            SELECT
                registers_for.username,
                AES_DECRYPT(registers_for.password, UNHEX(SHA2(:encryption_key, 256)), UNHEX(:encryption_iv)) AS password,
                registers_for.comment,
                registers_for.created_at,
                users.first_name,
                users.last_name,
                users.email,
                websites.website_name,
                websites.website_url
            FROM registers_for
            JOIN users ON registers_for.user_id = users.user_id
            JOIN websites ON registers_for.website_id = websites.website_id
            WHERE CONCAT_WS(' ',
                registers_for.username,
                users.email,
                users.first_name,
                users.last_name,
                websites.website_name,
                websites.website_url,
                registers_for.comment
            ) LIKE :query
        ");
        $stmt->bindParam(':query', $likeQuery, PDO::PARAM_STR);
        $stmt->bindValue(':encryption_key', ENCRYPTION_KEY, PDO::PARAM_STR);
        $stmt->bindValue(':encryption_iv', ENCRYPTION_IV, PDO::PARAM_STR);
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        // Log the error
        error_log("Search Query Error: " . $e->getMessage());
        return false;
    }
}


// Function to update an entry
function updateEntry($searchColumn, $searchValue, $updateColumn, $updateValue)
{
    global $db;

    // Allowed columns to prevent SQL injection
    $allowedSearchColumns = ['registers_for.username', 'users.email', 'websites.website_name'];
    $allowedUpdateColumns = ['registers_for.comment'];

    // Validate columns
    if (!in_array($searchColumn, $allowedSearchColumns) || !in_array($updateColumn, $allowedUpdateColumns)) {
        throw new Exception("Invalid column name.");
    }

    $likeSearchValue = '%' . $searchValue . '%';

    $stmt = $db->prepare("
        UPDATE registers_for
        JOIN users ON registers_for.user_id = users.user_id
        JOIN websites ON registers_for.website_id = websites.website_id
        SET $updateColumn = :updateValue
        WHERE $searchColumn LIKE :searchValue
    ");
    $stmt->bindParam(':updateValue', $updateValue, PDO::PARAM_STR);
    $stmt->bindParam(':searchValue', $likeSearchValue, PDO::PARAM_STR);

    return $stmt->execute();
}

// Function to insert a new entry
function insertEntry($firstName, $lastName, $email, $websiteName, $websiteUrl, $username, $password, $comment)
{
    global $db;

    try {
        $db->beginTransaction();

        // Insert or get user_id
        $stmtUser = $db->prepare("SELECT user_id FROM users WHERE email = :email");
        $stmtUser->bindParam(':email', $email, PDO::PARAM_STR);
        $stmtUser->execute();
        $user = $stmtUser->fetch();

        if ($user) {
            $userId = $user['user_id'];
        } else {
            $stmtInsertUser = $db->prepare("
                INSERT INTO users (first_name, last_name, email)
                VALUES (:first_name, :last_name, :email)
            ");
            $stmtInsertUser->bindParam(':first_name', $firstName, PDO::PARAM_STR);
            $stmtInsertUser->bindParam(':last_name', $lastName, PDO::PARAM_STR);
            $stmtInsertUser->bindParam(':email', $email, PDO::PARAM_STR);
            $stmtInsertUser->execute();
            $userId = $db->lastInsertId();
        }

        // Insert or get website_id
        $stmtWebsite = $db->prepare("SELECT website_id FROM websites WHERE website_url = :website_url");
        $stmtWebsite->bindParam(':website_url', $websiteUrl, PDO::PARAM_STR);
        $stmtWebsite->execute();
        $website = $stmtWebsite->fetch();

        if ($website) {
            $websiteId = $website['website_id'];
        } else {
            $stmtInsertWebsite = $db->prepare("
                INSERT INTO websites (website_name, website_url)
                VALUES (:website_name, :website_url)
            ");
            $stmtInsertWebsite->bindParam(':website_name', $websiteName, PDO::PARAM_STR);
            $stmtInsertWebsite->bindParam(':website_url', $websiteUrl, PDO::PARAM_STR);
            $stmtInsertWebsite->execute();
            $websiteId = $db->lastInsertId();
        }

        // Encrypt the password
        $encryptedPassword = encryptPassword($password);

        // Insert into registers_for
        $stmtAccount = $db->prepare("
            INSERT INTO registers_for (user_id, website_id, username, password, comment)
            VALUES (:user_id, :website_id, :username, :password, :comment)
        ");
        $stmtAccount->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $stmtAccount->bindParam(':website_id', $websiteId, PDO::PARAM_INT);
        $stmtAccount->bindParam(':username', $username, PDO::PARAM_STR);
        $stmtAccount->bindParam(':password', $encryptedPassword, PDO::PARAM_LOB);
        $stmtAccount->bindParam(':comment', $comment, PDO::PARAM_STR);
        $stmtAccount->execute();

        $db->commit();
        return true;
    } catch (Exception $e) {
        $db->rollBack();
        return false;
    }
}

// Function to encrypt a password
function encryptPassword($password)
{
    global $db;
    // Ensure the encryption mode is set correctly
    $db->exec("SET block_encryption_mode = 'aes-256-cbc'");
    $stmt = $db->prepare("
        SELECT AES_ENCRYPT(
            :password,
            UNHEX(SHA2(:encryption_key, 256)),
            UNHEX(:encryption_iv)
        ) AS encrypted_password
    ");
    $stmt->bindParam(':password', $password, PDO::PARAM_STR);
    $stmt->bindParam(':encryption_key', ENCRYPTION_KEY, PDO::PARAM_STR);
    $stmt->bindParam(':encryption_iv', ENCRYPTION_IV, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    return $row['encrypted_password'];
}

// Function to decrypt a password
function decryptPassword($encryptedPassword)
{
    global $db;
    $stmt = $db->prepare("
        SELECT AES_DECRYPT(
            :encryptedPassword,
            UNHEX(SHA2(:encryption_key, 256)),
            UNHEX(:encryption_iv)
        ) AS decrypted_password
    ");
    $stmt->bindParam(':encryptedPassword', $encryptedPassword, PDO::PARAM_LOB);
    $stmt->bindParam(':encryption_key', ENCRYPTION_KEY, PDO::PARAM_STR);
    $stmt->bindParam(':encryption_iv', ENCRYPTION_IV, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    return $row['decrypted_password'];
}

// Function to delete an entry
function deleteEntry($deleteColumn, $deleteValue)
{
    global $db;

    // Allowed columns to prevent SQL injection
    $allowedDeleteColumns = ['registers_for.username', 'users.email'];

    // Validate column
    if (!in_array($deleteColumn, $allowedDeleteColumns)) {
        throw new Exception("Invalid column name.");
    }

    $likeDeleteValue = '%' . $deleteValue . '%';

    $stmt = $db->prepare("
        DELETE registers_for
        FROM registers_for
        JOIN users ON registers_for.user_id = users.user_id
        WHERE $deleteColumn LIKE :deleteValue
    ");
    $stmt->bindParam(':deleteValue', $likeDeleteValue, PDO::PARAM_STR);

    return $stmt->execute();
}
?>
