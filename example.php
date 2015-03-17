<?php
date_default_timezone_set('America/Sao_Paulo');
// ###############################################################################
define ( "HASHMODE", 'ripemd160' ); // set hash mode here or in class instance
define ( "TOKENSECRET", 'many words for tokem secret frase' );
define ( "TOKENEXPIRE", 30 ); // time in minutes to token expire
define ( "OOEAUTHDEBUG", true ); // opcional for debug hash mode avaliable

echo date("Y-m-d H:i:s O");

include 'ooeAuth.class.php';

// $instance = new ooeAuth ( 'sha1' ); // set hash mode here or in constant , constant set are over construct

$instance = new ooeAuth ();

$tokenresponse = $instance->requestToken(); // create token independent hash mode is opcional

$token=$tokenresponse['token'];

echo '<pre>';
print_r ( $tokenresponse ); // check valid tokem
echo '</pre>';


echo '<pre>';
print_r ( $instance->checkToken ( $token ) ); // check valid tokem
echo '</pre>';

echo '<pre>';
print_r ( $instance->checkToken ( $token . 'erro' ) ); // check tokem invalid
echo '</pre>';

echo '<pre>';
$password = $instance->createNewPassword ( '#@$1234abcd' ); // create new password
echo '</pre>';

echo '<pre>';
print_r ( $instance->checkPassword ( '#@$1234abcd', $password ) ); // check valid password
echo '</pre>';

echo '<pre>';
print_r ( $instance->checkPassword ( '#@$1234abcd' . 'erro', $password ) ); // check invalid password
echo '</pre>';
