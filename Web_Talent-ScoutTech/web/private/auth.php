<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = FALSE;

# Check whether a pair of user and password are valid; returns true if valid.
function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    // Preparar la consulta SQL con un parámetro enlazado
    $stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');
    $stmt->bindValue(':username', $user, SQLITE3_TEXT);

    // Ejecutar la consulta
    $result = $stmt->execute();
    $row = $result->fetchArray();

    if(!isset($row['password'])) return FALSE;

    // Verificar la contraseña
    if ($password == $row['password']) {
        $userId = $row['userId'];
        $_COOKIE['userId'] = $userId;
        return TRUE;
    } else {
        return FALSE;
    }
}
# On login
if (isset($_POST['username'])) {		
	$_COOKIE['user'] = $_POST['username'];
    if(isset($_POST['password']))
	    $_COOKIE['password'] = $_POST['password'];
    else
        $_COOKIE['password'] = "";
} else {
    if (!isset($_POST['Logout']) && !isset($_COOKIE['user'])) {
        $_COOKIE['user'] = "";
        $_COOKIE['password'] = "";
    }
}

# On logout
if (isset($_POST['Logout'])) {
	# Delete cookies
	setcookie('user', FALSE);
	setcookie('password', FALSE);
	setcookie('userId', FALSE);
	
	unset($_COOKIE['user']);
	unset($_COOKIE['password']);
	unset($_COOKIE['userId']);

	header("Location: index.php");
}


# Check user and password
if (isset($_COOKIE['user']) && isset($_COOKIE['password'])) {
	if (areUserAndPasswordValid($_COOKIE['user'], $_COOKIE['password'])) {
		$login_ok = TRUE;
		$error = "";
	} else {
		$login_ok = FALSE;
		$error = "Invalid user or password.<br>";
	}
} else {
	$login_ok = FALSE;
	$error = "This page requires you to be logged in.<br>";
}

if ($login_ok == FALSE) {

?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= $error ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username"><br>
                    <label>Password</label>
                    <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
    <?php
    exit (0);
}

setcookie('user', $_COOKIE['user']);
setcookie('password', $_COOKIE['password']);


?>
