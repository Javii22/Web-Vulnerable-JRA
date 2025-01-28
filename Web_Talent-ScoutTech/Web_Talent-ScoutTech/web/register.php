<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Iniciar la sesión con configuración segura
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'secure' => true, // Solo en HTTPS
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

# Regenerar ID de sesión tras autenticación exitosa
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    # Validar token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Solicitud no válida.");
    }

    # Validar y sanitizar entradas
    if (!isset($_POST['username'], $_POST['password'])) {
        die("Datos incompletos.");
    }

    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (!preg_match('/^[a-zA-Z0-9_]{5,20}$/', $username)) {
        die("El nombre de usuario debe tener entre 5 y 20 caracteres alfanuméricos.");
    }

    if (strlen($password) < 8) {
        die("La contraseña debe tener al menos 8 caracteres.");
    }

    # Hash seguro para la contraseña
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    # Preparar e insertar en la base de datos
    $username = SQLite3::escapeString($username);

    $query = "INSERT INTO users (username, password) VALUES ('$username', '$hashed_password')";

    if (!$db->query($query)) {
        error_log("Error en la consulta: " . $db->lastErrorMsg());
        die("Ocurrió un error. Por favor, inténtelo de nuevo más tarde.");
    }

    # Validar sesión del usuario
    $_SESSION['user_id'] = $db->lastInsertRowID();

    if ($_SESSION['user_id'] !== $db->lastInsertRowID()) {
        die("Sesión inválida.");
    }

    # Redirigir después del registro exitoso
    header("Location: list_players.php");
    exit;
}

# Generar un nuevo token CSRF
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

?>
<!doctype html>
<html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Players list</title>
    </head>
    <body>
        <header>
            <h1>Register</h1>
        </header>
        <main class="player">
            <form action="#" method="post">
                <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                <label>Username:</label>
                <input type="text" name="username" required pattern="[a-zA-Z0-9_]{5,20}" title="5-20 caracteres alfanuméricos">
                <label>Password:</label>
                <input type="password" name="password" required minlength="8" title="Mínimo 8 caracteres">
                <input type="submit" value="Send">
            </form>
            <form action="#" method="post" class="menu-form">
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en producción segura</h4>
            < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
        </footer>
    </body>
</html>
