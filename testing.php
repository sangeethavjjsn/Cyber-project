<?php
// SQL Injection
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);

// Cross-Site Scripting (XSS)
echo "<div>" . $_GET['name'] . "</div>";

// Local File Inclusion (LFI)
include($_GET['page'] . ".php");

// Insecure File Upload
if (isset($_FILES['file'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
}

// Weak Cryptography (MD5, insecure)
$password = $_POST['password'];
$hash = md5($password);

// Command Execution
$cmd = $_GET['cmd'];
system($cmd);
?>
