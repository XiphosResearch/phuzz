<?php   
if(isset($_POST['url'])) {
    $_POST = array_map("urldecode",$_POST);
    echo file_get_contents("http://".$_POST['url']);
} else {
    echo "test2";
}
?>