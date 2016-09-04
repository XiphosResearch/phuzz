<?php
if(empty($_GET["url"]))
   $url = 'step_welcome.php';
else
   $url = $_GET["url"];
?>
<p><? include('step/'.$url) ?></p>