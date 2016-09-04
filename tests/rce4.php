<?php
   $host = 'google';
   if (isset( $_GET['host'] ) )
      $host = $_GET['host'];
   system("nslookup " . $host);
?>

<form method="get">
   <select name="host">
      <option value="google.com">google</option>
      <option value="yahoo.com">yahoo</option>
   </select>
   <input type="submit">
</form>