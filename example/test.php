<?php

error_reporting(E_ALL);
ini_set("display_errors", 1); 

require_once('../KLGPasswordValidator.php');

$passwordValidatorConfiguration = array(
		'minimumLength' => 8,
		'containsNumber' => true,
		'containsSpecialCharacter' => true,
		'rejectSubstrings' => array('secret','topsecret','open','unlock')
);

$validator = new KLGPasswordValidator($passwordValidatorConfiguration);

$password = isset($_POST['password']) ? $_POST['password'] : '';

if ($password == '') exit;

$validator->setPassword($password);

if (!$validator->isPasswordValid()) {
	$errors = $validator->getErrors();
	
	$s = '<ul>';
	foreach($errors as $error) {
		$s.='<li>'.$validator->getHumanReadableErrorMessage($error).'</li>';
	}
	$s.= '</ul>';
	
	echo '<div id="error" style="width:600px; border: 1px solid red; background-color: #ffaaaa; color:red;">'.$s.'</div>';
} else {
	$s = "Passwort ist okay, der Score beträgt: ".$validator->getScore();
	echo '<div id="success" style="width:600px; border: 1px solid green; background-color: #aaffaa; color:green;padding:10px;">'.$s.'</div>';
}

