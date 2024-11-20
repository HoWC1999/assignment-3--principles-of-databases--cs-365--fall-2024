<?php
// index.php

require_once 'includes/config.php';
require_once 'includes/helpers.php';

// Handle actions
if (isset($_REQUEST['action'])) {
    $action = $_REQUEST['action'];

    switch ($action) {
        case 'search':
            if (isset($_REQUEST['action'])) {
                $action = $_REQUEST['action'];
                switch ($action) {
                    case 'search':
                        if (isset($_GET['query'])) {
                            $query = $_GET['query'];
                            $results = searchEntries($query);
                            if ($results) {
                                echo "<h2>Search Results</h2>";
                                echo "<table>";
                                echo "<thead>";
                                echo "<tr>
                                        <th>Username</th>
                                        <th>Password</th>
                                        <th>Comment</th>
                                        <th>Created At</th>
                                        <th>User First Name</th>
                                        <th>User Last Name</th>
                                        <th>User Email</th>
                                        <th>Website Name</th>
                                        <th>Website URL</th>
                                      </tr>";
                                echo "</thead>";
                                echo "<tbody>";
                                foreach ($results as $row) {
                                    echo "<tr>";
                                    echo "<td>" . htmlspecialchars($row['username'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['password'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['comment'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['created_at'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['first_name'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['last_name'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['email'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['website_name'] ?? '') . "</td>";
                                    echo "<td>" . htmlspecialchars($row['website_url'] ?? '') . "</td>";
                                    echo "</tr>";
                                }
                                echo "</tbody>";
                                echo "</table>";
                            } else {
                                echo "<p>No results found.</p>";
                            }
                        }
                        break;
                    default:
                        echo "<p>Invalid action.</p>";
                        break;
                }
            }
        case 'update':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $searchColumn = $_POST['search_column'];
                $searchValue = $_POST['search_value'];
                $updateColumn = $_POST['update_column'];
                $updateValue = $_POST['update_value'];
                // Prefix columns with table names to match allowed columns
                if ($searchColumn === 'username') {
                    $searchColumn = 'registers_for.username';
                } elseif ($searchColumn === 'email') {
                    $searchColumn = 'users.email';
                } elseif ($searchColumn === 'website_name') {
                    $searchColumn = 'websites.website_name';
                }
                if ($updateColumn === 'comment') {
                    $updateColumn = 'registers_for.comment';
                }
                try {
                    $result = updateEntry($searchColumn, $searchValue, $updateColumn, $updateValue);
                    if ($result) {
                        echo "<p>Update successful.</p>";
                    } else {
                        echo "<p>Update failed.</p>";
                    }
                } catch (Exception $e) {
                    echo "<p>Error: " . htmlspecialchars($e->getMessage()) . "</p>";
                }
            }
            break;
        case 'insert':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $firstName   = $_POST['first_name'];
                $lastName    = $_POST['last_name'];
                $email       = $_POST['email'];
                $websiteName = $_POST['website_name'];
                $websiteUrl  = $_POST['website_url'];
                $username    = $_POST['username'];
                $password    = $_POST['password'];
                $comment     = $_POST['comment'];

                $result = insertEntry($firstName, $lastName, $email, $websiteName, $websiteUrl, $username, $password, $comment);

                if ($result) {
                    echo "<p>Entry added successfully.</p>";
                } else {
                    echo "<p>Failed to add entry.</p>";
                }
            }
            break;
        case 'delete':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $deleteColumn = $_POST['delete_column'];
                $deleteValue  = $_POST['delete_value'];
                // Prefix columns with table names to match allowed columns
                if ($deleteColumn === 'username') {
                    $deleteColumn = 'registers_for.username';
                } elseif ($deleteColumn === 'email') {
                    $deleteColumn = 'users.email';
                }
                try {
                    $result = deleteEntry($deleteColumn, $deleteValue);

                    if ($result) {
                        echo "<p>Entry deleted successfully.</p>";
                    } else {
                        echo "<p>Failed to delete entry.</p>";
                    }
                } catch (Exception $e) {
                    echo "<p>Error: " . htmlspecialchars($e->getMessage()) . "</p>";
                }
            }
            break;
        default:
            echo "<p>Invalid action.</p>";
            break;
    }
}
?>

<!DOCTYPE html>
<html>
    <head>
        <title>Password Manager</title>
        <link rel="stylesheet" type="text/css" href="css/style.css">
    </head>
    <body>
        <!-- Navigation Menu -->
        <nav>
            <div class="container">
                <a href="index.php">Home</a>
                <a href="?form=search">Search</a>
                <a href="?form=insert">Insert</a>
                <a href="?form=update">Update</a>
                <a href="?form=delete">Delete</a>
            </div>
        </nav>
        <div class="container">
            <!-- Display Forms Based on the 'form' Query Parameter -->
            <?php
            if (isset($_GET['form'])) {
                $form = $_GET['form'];
                switch ($form) {
                    case 'search':
                        if (isset($_GET['query'])) {
                            $query = $_GET['query'];
                            $results = searchEntries($query);
                            if ($results) {
                                echo "<h2>Search Results</h2>";
                                echo "<table>";
                                echo "<thead>";
                                echo "<tr>
                                        <th>Username</th>
                                        <th>Password</th>
                                        <th>Comment</th>
                                        <th>Created At</th>
                                        <th>User First Name</th>
                                        <th>User Last Name</th>
                                        <th>User Email</th>
                                        <th>Website Name</th>
                                        <th>Website URL</th>
                                    </tr>";
                                echo "</thead>";
                                echo "<tbody>";
                                foreach ($results as $row) {
                                    echo "<tr>";
                                    echo "<td data-label='Username'>" . htmlspecialchars($row['username'] ?? '') . "</td>";
                                    echo "<td data-label='Password'>" . htmlspecialchars($row['password'] ?? '') . "</td>";
                                    echo "<td data-label='Comment'>" . htmlspecialchars($row['comment'] ?? '') . "</td>";
                                    echo "<td data-label='Created At'>" . htmlspecialchars($row['created_at'] ?? '') . "</td>";
                                    echo "<td data-label='User First Name'>" . htmlspecialchars($row['first_name'] ?? '') . "</td>";
                                    echo "<td data-label='User Last Name'>" . htmlspecialchars($row['last_name'] ?? '') . "</td>";
                                    echo "<td data-label='User Email'>" . htmlspecialchars($row['email'] ?? '') . "</td>";
                                    echo "<td data-label='Website Name'>" . htmlspecialchars($row['website_name'] ?? '') . "</td>";
                                    echo "<td data-label='Website URL'>" . htmlspecialchars($row['website_url'] ?? '') . "</td>";
                                    echo "</tr>";
                                }
                                echo "</tbody>";
                                echo "</table>";
                            } else {
                                echo "<p class='message error'>No results found.</p>";
                            }
                        } else {
                            // If 'query' is not set, display the search form
                            ?>
                            <h2>Search Entries</h2>
                            <form action="index.php?action=search" method="GET">
                                <input type="hidden" name="action" value="search">
                                <input type="text" name="query" placeholder="Search..." required>
                                <button type="submit" class="button">Search</button>
                            </form>
                            <?php
                        }
                        break;

                    case 'update':
                        ?>
                        <h2>Update an Entry</h2>
                        <form action="index.php" method="POST">
                            <input type="hidden" name="action" value="update">
                            <label for="search_column">Search Column:</label>
                            <select name="search_column" id="search_column" required>
                                <option value="username">Username</option>
                                <option value="website_name">Website Name</option>
                                <option value="website_url">Website URL</option>
                                <option value="comment">Comment</option>
                            </select>
                            <input type="text" name="search_value" placeholder="Search Value" required>
                            <label for="update_column">Update Column:</label>
                            <select name="update_column" id="update_column" required>
                                <option value="first_name">First Name</option>
                                <option value="last_name">Last Name</option>
                                <option value="email">Email</option>
                                <option value="username">Username</option>
                                <option value="password">Password</option>
                                <option value="website_name">Website Name</option>
                                <option value="website_url">Website URL</option>
                                <option value="comment">Comment</option>
                            </select>
                            <input type="text" name="update_value" placeholder="Update Value" required>
                            <button type="submit">Update</button>
                        </form>
                        <?php
                        break;

                    case 'insert':
                        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                            // Retrieve and sanitize POST data
                            $firstName   = trim($_POST['first_name'] ?? '');
                            $lastName    = trim($_POST['last_name'] ?? '');
                            $email       = trim($_POST['email'] ?? '');
                            $websiteName = trim($_POST['website_name'] ?? '');
                            $websiteUrl  = trim($_POST['website_url'] ?? '');
                            $username    = trim($_POST['username'] ?? '');
                            $password    = $_POST['password'] ?? ''; // Passwords may contain spaces
                            $comment     = trim($_POST['comment'] ?? '');

                            // Validate required fields
                            if (empty($firstName) || empty($lastName) || empty($email) || empty($websiteName) || empty($websiteUrl) || empty($username) || empty($password)) {
                                echo "<p class='message error'>Please fill in all required fields.</p>";
                            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                                echo "<p class='message error'>Please enter a valid email address.</p>";
                            } else {
                            // Proceed with insertion
                                $result = insertEntry($firstName, $lastName, $email, $websiteName, $websiteUrl, $username, $password, $comment);

                                if ($result) {
                                    echo "<p class='message success'>Entry added successfully.</p>";
                                } else {
                                    echo "<p class='message error'>Failed to add entry. Please try again later.</p>";
                                }
                            }
                        } else {
                            // Display insert form
                            ?>
                            <section class="database-query">
                                <h2>Insert New Entry</h2>
                                <form action="index.php?action=insert" method="POST">
                                    <label for="first_name">First Name:</label>
                                    <input type="text" name="first_name" id="first_name" placeholder="First Name" required>

                                    <label for="last_name">Last Name:</label>
                                    <input type="text" name="last_name" id="last_name" placeholder="Last Name" required>

                                    <label for="email">Email Address:</label>
                                    <input type="email" name="email" id="email" placeholder="Email Address" required>

                                    <label for="website_name">Website Name:</label>
                                    <input type="text" name="website_name" id="website_name" placeholder="Website Name" required>

                                    <label for="website_url">Website URL:</label>
                                    <input type="text" name="website_url" id="website_url" placeholder="Website URL" required>

                                    <label for="username">Username:</label>
                                    <input type="text" name="username" id="username" placeholder="Username" required>

                                    <label for="password">Password:</label>
                                    <input type="password" name="password" id="password" placeholder="Password" required>

                                    <label for="comment">Comment:</label>
                                    <textarea name="comment" id="comment" placeholder="Comment"></textarea>

                                    <button type="submit" class="button">Add Entry</button>
                                </form>
                            </section>
                        <?php
                    }
                        break;
                    case 'delete':
                        ?>
                        <h2>Delete an Entry</h2>
                        <form action="index.php" method="POST">
                            <input type="hidden" name="action" value="delete">
                            <label for="delete_column">Delete Column:</label>
                            <select name="delete_column" id="delete_column" required>
                                <option value="username">Username</option>
                                <option value="email">Email</option>
                                <option value="website_name">Website Name</option>
                                <option value="website_url">Website URL</option>
                            </select>

                            <input type="text" name="delete_value" placeholder="Value" required>

                            <button type="submit">Delete Entry</button>
                        </form>
                        <?php
                        break;
                    default:
                        echo "<p>Invalid form.</p>";
                        break;
                }
            } else {
                // Default content or instructions
                echo "<h2>Welcome to the Password Manager</h2>";
                echo "<p>Select an action from the menu above.</p>";
            }
            ?>
            <!-- Refresh Button -->
            <a href="index.php" class="button-refresh">Refresh Page</a>
        </div>
        <!-- Footer -->
        <footer>
            &copy; <?php echo date("Y"); ?> Password Manager
        </footer>
    </body>
</html>
