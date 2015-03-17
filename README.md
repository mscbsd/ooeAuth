# ooeAuth
// Create a customized token with expire time and login safe

// Basic usage

// Set your timezone

date_default_timezone_set('America/Sao_Paulo');

// Set you prefered hash algoritm

define ( "HASHMODE", 'ripemd160' ); // set hash mode here or in class instance

// Set you secret token key frase

define ( "TOKENSECRET", 'many words for tokem secret frase' );

// Set in minutes your token expire time

define ( "TOKENEXPIRE", 30 ); // time in minutes to token expire

// Opcional set for debug if your settings are avaliable in php

define ( "OOEAUTHDEBUG", true ); // opcional for debug hash mode avaliable

// instance class

$instance = new ooeAuth ();

// This token have a expired time for checking

// create a token whit expire time

$tokenresponse = $instance->requestToken()


// example api json token response

echo json_encode($tokenresponse);

// check valid token example

if(array_key_exists ( $token , $_POST )){


echo '<pre>';
print_r ( $instance->checkToken ( $token ) ); // check valid tokem
echo '</pre>';


}

// Create a password to store in your database

echo '<pre>';
$password = $instance->createNewPassword ( '#@$1234abcd' ); // create new password
echo '</pre>';

// Checking if passord register are valid safe from injection , use post 

if(array_key_exists ( $token , $_POST )){

// Capture registred passorwd from your database using username or email

if (filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {

$sanitized_email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);

SELECT password FROM mytable WHERE email='$sanitized_email' ; // get password from select username for security

$passworddatabase=$result[0]['password'];

// Check if password hash combine whith passord hash calc

echo '<pre>';
print_r ( $instance->checkPassword ( $_POST['password'], $passworddatabase ) ); // check valid password
echo '</pre>';

  }
  
}
