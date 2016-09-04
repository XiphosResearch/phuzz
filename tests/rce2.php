<?php
$status = $_GET['status'];
$ns  = $_GET['ns'];
$host   = $_GET['host'];
$query_type   = $_GET['query_type']; // ANY, MX, A , etc.
$ip     = $_SERVER['REMOTE_ADDR'];
$self   = $_SERVER['PHP_SELF'];

$host = trim($host);
$host = strtolower($host);
echo("<span class=\"plainBlue\"><b>Executing : <u>dig @$ns $host $query_type</u></b><br>");
echo '<pre>';
system ("dig @$ns $host $query_type");