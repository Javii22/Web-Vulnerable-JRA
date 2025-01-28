<?php
require_once dirname(__FILE__) . '/private/conf.php';
require dirname(__FILE__) . '/private/auth.php';

$name = $_GET['name'] ?? '';

try {
    // Preparar la consulta
    $stmt = $db->prepare("SELECT playerid, name, team FROM players WHERE name = :name ORDER BY playerId DESC");
    $stmt->bindValue(':name', $name, SQLITE3_TEXT);

    // Ejecutar la consulta
    $result = $stmt->execute();

    // Recuperar los datos en un array
    $players = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $players[] = $row;
    }

    $result->finalize(); // Liberar el resultado
} catch (Exception $e) {
    die("Error en la consulta: " . $e->getMessage());
}
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Búsqueda</title>
    <style>
        .container {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 60vh;
            text-align: center;
        }
        .no-results {
            font-size: 18px;
            font-weight: bold;
            color: #333;
            margin-bottom: 20px;
        }
        .button-container {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        .btn {
            text-decoration: none;
            background-color: #FDD835;
            color: black;
            padding: 10px 15px;
            border-radius: 5px;
            font-weight: bold;
            border: none;
            cursor: pointer;
        }
        .logout {
            background-color: #333;
            color: white;
        }
    </style>
</head>
<body>
<header class="listado">
    <h1>Búsqueda de <?php echo htmlspecialchars($name); ?></h1>
</header>
<main class="listado">
    <div class="container">
        <?php if (empty($players)): ?>
            <p class="no-results">No se encontró ningún usuario con el nombre "<?php echo htmlspecialchars($name); ?>".</p>
        <?php else: ?>
            <ul>
                <?php foreach ($players as $row): ?>
                    <li>
                        <div>
                            <span>Name: <?php echo htmlspecialchars($row['name']); ?></span>
                            <span>Team: <?php echo htmlspecialchars($row['team']); ?></span>
                        </div>
                        <div>
                            <a href="show_comments.php?id=<?php echo htmlspecialchars($row['playerid']); ?>">(show/add comments)</a>
                            <a href="insert_player.php?id=<?php echo htmlspecialchars($row['playerid']); ?>">(edit player)</a>
                        </div>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
        
        <div class="button-container">
            <a href="index.php" class="btn">Back to home</a>
            <a href="list_players.php" class="btn">Back to list</a>
            <form action="#" method="post" style="display:inline;">
                <input type="submit" name="Logout" value="Logout" class="btn logout">
            </form>
        </div>
    </div>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    <p>Please <a href="http://www.donate.co?amount=100&destination=ACMEScouting/">donate</a></p>
</footer>
</body>
</html>
