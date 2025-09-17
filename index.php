<?php


error_reporting(E_ALL);
ini_set('display_errors', 1);


$DB_HOST = 'localhost';
$DB_USER = 'root';
$DB_PASS = '';        
$DB_NAME = 'user_db';


$conn = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS);
if (!$conn) die("Connection failed: " . mysqli_connect_error());


mysqli_query($conn, "CREATE DATABASE IF NOT EXISTS `$DB_NAME` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
mysqli_select_db($conn, $DB_NAME);


mysqli_query($conn, "
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(150) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
");


$msg = '';
$logged_in = false;
$current_user = null;


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    $uname = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $pass  = $_POST['password'] ?? '';

    if ($uname === '' || $email === '' || $pass === '') {
        $msg = 'Please fill all fields.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg = ' Invalid email address.';
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username=? OR email=?");
        $stmt->bind_param("ss", $uname, $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $msg = '⚠️ Username or email already exists.';
        } else {
            $hashed = password_hash($pass, PASSWORD_BCRYPT);
            $ins = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $ins->bind_param("sss", $uname, $email, $hashed);
            if ($ins->execute()) $msg = '✅ Registration successful! Please login.';
            else $msg = '❌ Error: '.$ins->error;
            $ins->close();
        }
        $stmt->close();
    }
}


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $uname = trim($_POST['username'] ?? '');
    $pass  = $_POST['password'] ?? '';

    if ($uname === '' || $pass === '') {
        $msg = '⚠️ Enter username and password.';
    } else {
        $stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
        $stmt->bind_param("s", $uname);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            if (password_verify($pass, $row['password'])) {
                $logged_in = true;
                $current_user = $row;
                $msg = 'Login Successful!';
            } else $msg = 'Wrong password.';
        } else $msg = ' User not found.';
        $stmt->close();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Auth Demo</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:Arial,Helvetica,sans-serif;background:#000;color:#fff;min-height:100vh;display:flex;justify-content:center;align-items:center}
  .box{width:340px;background:rgba(0,0,0,0.75);padding:25px;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.6);text-align:center}
  h1{color:aqua;margin-bottom:16px}
  input{width:100%;padding:10px;margin:8px 0;border:none;border-radius:6px}
  button{width:100%;padding:12px;margin-top:10px;border:none;border-radius:6px;background:aqua;color:#000;font-weight:bold;cursor:pointer}
  .msg{margin-bottom:10px;color:yellow;font-weight:bold}
  .link{color:aqua;cursor:pointer;text-decoration:none}
</style>
</head>
<body>
<div class="box">
  <?php if ($msg !== ''): ?><div class="msg"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

  <?php if (!$logged_in): ?>
    <!-- Login -->
    <form id="loginForm" method="post">
      <h1>Login</h1>
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit" name="login">LOGIN</button>
      <p style="margin-top:10px">Not registered? <a class="link" onclick="toggleForms()">Register</a></p>
    </form>

    <!-- Register -->
    <form id="registerForm" method="post" style="display:none">
      <h1>Register</h1>
      <input type="text" name="username" placeholder="Username" required>
      <input type="email" name="email" placeholder="Email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit" name="register">REGISTER</button>
      <p style="margin-top:10px">Already registered? <a class="link" onclick="toggleForms()">Login</a></p>
    </form>
  <?php else: ?>
    <!-- Success -->
    <h1>Welcome <?= htmlspecialchars($current_user['username']) ?> 🎉</h1>
    <p style="margin-top:10px;font-size:14px;color:#ccc">Login Successful</p>
  <?php endif; ?>
</div>

<script>
function toggleForms(){
  const login = document.getElementById('loginForm');
  const reg   = document.getElementById('registerForm');
  if (login.style.display === 'none') {
    login.style.display='block'; reg.style.display='none';
  } else {
    login.style.display='none'; reg.style.display='block';
  }
}
</script>
</body>
</html>
