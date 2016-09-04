<?php
	passthru("./get_quarters.py " . escapeshellarg($_POST["course_id"]));
?>