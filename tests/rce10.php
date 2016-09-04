<?php
// So dangerous!
system(sprintf("swrite 21 115200 %02X %02X %02X %02X", intval($_GET['address'],16), intval($_GET['r']), intval($_GET['g']), intval($_GET['b'])));
?>