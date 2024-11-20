<?php

function searchEntries($query)
// Function to search for entries based on a query
{
    global $db;
    // Ensure the encryption mode is set correctly
    $db->exec("SET block_encryption_mode = 'aes-256-cbc'");
    $likeQuery = '%' . $query . '%';

    try {
        // Prepare the SELECT statement with aliases
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


function updateEntry($searchColumn, $searchValue, $updateColumn, $updateValue)
{
    global $db;

    // Define allowed columns with proper table aliases
    $columnMapping = [
        // Registers_For Table Columns
        'registers_for.username' => 'rf.username',
        'registers_for.password' => 'rf.password',
        'registers_for.comment'  => 'rf.comment',

        // Users Table Columns
        'users.first_name' => 'u.first_name',
        'users.last_name'  => 'u.last_name',
        'users.email'      => 'u.email',

        // Websites Table Columns
        'websites.website_name' => 'w.website_name',
        'websites.website_url'  => 'w.website_url',

        // Add any additional columns here as needed
    ];

    // Log received parameters for debugging
    error_log("Update Request Received:");
    error_log("Search Column: " . $searchColumn);
    error_log("Search Value: " . $searchValue);
    error_log("Update Column: " . $updateColumn);
    error_log("Update Value: " . $updateValue);

    // Validate and map the search column
    if (!array_key_exists($searchColumn, $columnMapping)) {
        error_log("Invalid search column name provided: " . $searchColumn);
        throw new Exception("Invalid search column name.");
    }
    $qualifiedSearchColumn = $columnMapping[$searchColumn];

    // Validate and map the update column
    if (!array_key_exists($updateColumn, $columnMapping)) {
        error_log("Invalid update column name provided: " . $updateColumn);
        throw new Exception("Invalid update column name.");
    }
    $qualifiedUpdateColumn = $columnMapping[$updateColumn];

    if ($updateColumn === 'registers_for.password') {
        // Ensure the encryption mode is set correctly
        $updateValue = encryptPassword($updateValue);
    }

    // Construct the LIKE pattern for SQL
    $likeSearchValue = '%' . $searchValue . '%';

    // Additional Validation for Specific Columns (e.g., URL)
    if ($updateColumn === 'websites.website_url' && !filter_var($updateValue, FILTER_VALIDATE_URL)) {
        throw new Exception("Invalid URL format for website_url.");
    }

    try {
        // Begin transaction
        $db->beginTransaction();

        // Prepare the UPDATE statement with aliases
        $stmt = $db->prepare("
            UPDATE registers_for AS rf
            JOIN users AS u ON rf.user_id = u.user_id
            JOIN websites AS w ON rf.website_id = w.website_id
            SET $qualifiedUpdateColumn = :updateValue
            WHERE $qualifiedSearchColumn LIKE :searchValue
        ");

        // Bind the parameters using bindValue()
        $stmt->bindParam(':updateValue', $updateValue, PDO::PARAM_STR);
        $stmt->bindValue(':searchValue', $likeSearchValue, PDO::PARAM_STR);

        // Execute the statement
        $stmt->execute();

        // Get the number of affected rows
        $affectedRows = $stmt->rowCount();

        // Commit the transaction
        $db->commit();

        // Log the update activity
        if ($affectedRows > 0) {
            error_log("Update Entry Success: {$affectedRows} entry(s) updated. Column '{$updateColumn}' set to '{$updateValue}' where '{$searchColumn}' LIKE '{$likeSearchValue}'.");
        } else {
            error_log("Update Entry Info: No entries matched for update based on '{$searchColumn}' LIKE '{$likeSearchValue}'.");
        }

        return $affectedRows;
    } catch (PDOException $e) {
        // Rollback the transaction on error
        $db->rollBack();
        error_log("Update Entry Error (PDOException): " . $e->getMessage());
        return false;
    } catch (Exception $e) {
        // Handle other exceptions
        $db->rollBack();
        error_log("Update Entry Error (Exception): " . $e->getMessage());
        return false;
    }
}

// Function to insert a new entry
function insertEntry($firstName, $lastName, $email, $websiteName, $websiteUrl, $username, $password, $comment)
{
    global $db;

    try {
        // Begin transaction
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
    $stmt->bindValue(':encryption_key', ENCRYPTION_KEY, PDO::PARAM_STR);
    $stmt->bindValue(':encryption_iv', ENCRYPTION_IV, PDO::PARAM_STR);
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
    $stmt->bindValue(':encryption_key', ENCRYPTION_KEY, PDO::PARAM_STR);
    $stmt->bindValue(':encryption_iv', ENCRYPTION_IV, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    return $row['decrypted_password'];
}

function deleteEntry($deleteColumn, $deleteValue)
{
    global $db;

    // Define allowed columns with proper table prefixes
    $columnMapping = [
        'username'     => 'rf.username',
        'email'        => 'u.email',
        'website_name' => 'w.website_name',
        'website_url'  => 'w.website_url'
    ];

    // Validate and map the column
    if (!array_key_exists($deleteColumn, $columnMapping)) {
        throw new Exception("Invalid column name.");
    }

    $qualifiedColumn = $columnMapping[$deleteColumn];
    $likeDeleteValue = '%' . $deleteValue . '%';

    try {
        // Begin transaction
        $db->beginTransaction();

        // Prepare the DELETE statement with aliases
        $stmt = $db->prepare("
            DELETE rf
            FROM registers_for AS rf
            JOIN users AS u ON rf.user_id = u.user_id
            JOIN websites AS w ON rf.website_id = w.website_id
            WHERE $qualifiedColumn LIKE :deleteValue
        ");

        // Bind the value using bindValue()
        $stmt->bindValue(':deleteValue', $likeDeleteValue, PDO::PARAM_STR);

        // Execute the statement
        $stmt->execute();

        // Get the number of affected rows
        $affectedRows = $stmt->rowCount();

        // Commit the transaction
        $db->commit();

        // Log the deletion activity
        if ($affectedRows > 0) {
            error_log("Delete Entry Success: {$affectedRows} entry(s) deleted based on {$deleteColumn} LIKE {$likeDeleteValue}");
        } else {
            error_log("Delete Entry Info: No entries matched for deletion based on {$deleteColumn} LIKE {$likeDeleteValue}");
        }

        return $affectedRows;
    } catch (PDOException $e) {
        // Rollback the transaction on error
        $db->rollBack();
        error_log("Delete Entry Error: " . $e->getMessage());
        return false;
    }
}
?>
