<?php
/**
 * Classe para gerencia de senha e token criptografado customizado
 * Token customizado com propiedade embutida de data de expiração 
 * Senha customizada 
 * @author Marcelo Soares da Costa
 * @email msbsd at gmail dot com
 * @copyright Marcelo Soares da Costa 2015.
 * @license FreeBSD http://www.freebsd.org/copyright/freebsd-license.html
 * @version 1.0
 * @access public
 * @package OOE
 * @data 2015-03-13
 * @page
 */


class ooeAuth {
	private $hashmode = FALSE;
	private $avaliablehashModeArray = array ();
	private $keyResult = NULL;
	private $checkMode = FALSE;
	protected $mode;
	private $salt = NULL;
	private $pwd = FALSE;
	private $hashpwd = NULL;
	private $expired = NULL;
	private $hashtoken;
	private $tokencompare;
	private $newexpired = NULL;
	private $buuumm = array ();
	private $pwdRequest = NULL;
	private $pwdRegistred = NULL;
	private $RESPONSE = array ();
	
	/**
	 * Class construct
	 *
	 * @param string $hashmode        	
	 * @throws Exception
	 */
	function __construct($hashmode = null) {
		try {
			self::registerHashMode ( $hashmode );
		} catch ( Exception $e ) {
			if (defined ( 'OOEAUTHDEBUG' )) {
				if (OOEAUTHDEBUG) {
					echo '<pre>';
					print_r ( hash_algos () );
					echo '</pre>';
				}
			}
			throw new Exception ( $e->getMessage () );
		}
		
		if (! defined ( 'TOKENSECRET' )) {
			throw new Exception ( " Constant TOKENSECRET not defined " );
		}
		
		if (! defined ( 'TOKENEXPIRE' )) {
			define ( "TOKENEXPIRE", 30 ); // if not set TOKENEXPIRE , expire in 30 min
		}
	}
	
	/**
	 * Check hashing algorithm avaliable
	 * 
	 * @param string $hashmode        	
	 * @return boolean|string
	 */
	private function checkHashMode($hashmode) {
		$avaliablehashModeArray = hash_algos ();
		$keyResult = array_search ( $hashmode, $avaliablehashModeArray );
		
		if ($keyResult == NULL) {
			return false;
		} else {
			return strtolower ( $hashmode );
		}
	}
	
	/**
	 * Check registred hashing algorithm
	 * 
	 * @param string $hashmode        	
	 * @throws Exception
	 */
	private function registerHashMode($hashmode) {
		if (! defined ( 'HASHMODE' )) {
			$checkMode = self::checkHashMode ( strtolower ( $hashmode ) );
			
			if ($checkMode) {
				define ( "HASHMODE", $checkMode );
			} else {
				throw new Exception ( $hashmode . " hashing algorithm not supported " );
			}
		} else {
			$checkMode = self::checkHashMode ( HASHMODE );
			if (! $checkMode) {
				throw new Exception ( HASHMODE . " hashing algorithm not supported " );
			}
		}
	}
	
	/**
	 * Create a salt password
	 * 
	 * @return string
	 */
	private function createSaltPwd() {
		return substr ( md5 ( uniqid ( rand (), true ) ), 0, 5 );
	}
	
	/**
	 * Create a hash password with passed algorithm
	 * 
	 * @param string $mode        	
	 * @param string $salt        	
	 * @param string $pwd        	
	 * @return string
	 */
	private function hashModePwd($mode, $salt, $pwd) {
		return hash_hmac ( $mode, $pwd, $salt, FALSE );
	}
	
	/**
	 * Create a cutomized hash password with passed algorithm
	 * 
	 * @param string $mode        	
	 * @param string $salt        	
	 * @param string $pwd        	
	 * @return string
	 */
	private function hashModePwdCuston($mode, $salt, $pwd) {
		$hashpwd = self::hashModePwd ( strtolower ( $mode ), $salt, $pwd );
		return strtoupper ( $mode ) . '$' . $salt . '$' . $hashpwd;
	}
	
	/**
	 * Create a new cutomized hash password with registred algorithm
	 * 
	 * @param string $pwd        	
	 * @param string $hashmode        	
	 * @throws Exception
	 * @return string
	 */
	final public function createNewPassword($pwd, $hashmode = false) {
		if (($hashmode) and ($hashmode != HASHMODE)) {
			$checkMode = self::checkHashMode ( $hashmode );
			if ($checkMode) {
				$mode = $hashmode;
			} else {
				throw new Exception ( $hashmode . " hashing algorithm not supported " );
			}
		} else {
			$mode = strtolower ( HASHMODE );
		}
		$salt = self::createSaltPwd ();
		return self::hashModePwdCuston ( $mode, $salt, $pwd );
	}
	
	
	/**
	 * @ Create a customize token
	 *
	 * @access public
	 * @param string $mode
	 * @return string
	 */
	private function createToken() {
		$salt = self::createSaltPwd ();
		$expired =  intval(time() + (TOKENEXPIRE * 60));
		$hashtoken = self::hashModePwd ( strtolower ( HASHMODE ), $salt, $expired . TOKENSECRET );
		$token = $expired . '$' . $salt . '$' . $hashtoken;
		return $token;
	}
	
	/**
	 * @ Response a customize token
	 *
	 * @access public
	 * @param string $mode        	
	 * @return string
	 */
	final public function requestToken() {
		$token = self::createToken ( );
		$buuumm = explode ( '$', $token );
		$expired = $buuumm [0];
		$RESPONSE ['mensage'] = 'new token';
		$RESPONSE ['expired'] = date("Y-m-d H:i:s O",$expired);
		$RESPONSE ['token'] = $token;
		return $RESPONSE;
	}
	
	/**
	 * @Check expired and valid token
	 *
	 * @param string $token        	
	 * @return array
	 */
	final public function checkToken($token) {
		unset ( $RESPONSE );
		$buuumm = explode ( '$', $token );
		$expired = $buuumm [0];
		$salt = $buuumm [1];
		$hashtoken = self::hashModePwd ( strtolower (HASHMODE), $salt, $expired . TOKENSECRET );
		$tokencompare = $expired . '$' . $salt . '$' . $hashtoken;
		$newexpired = intval ( microtime ( true ) + (TOKENEXPIRE * 1000) );
		
		if ($expired < intval ( microtime ( true ) )) {
			$RESPONSE ['mensage'] = 'expired token';
			$RESPONSE ['valid'] = 'false';
			$RESPONSE ['rejected'] = $token;
			$RESPONSE ['expired'] = $newexpired;
			$RESPONSE ['token'] = self::createToken (  );
		} else {
			if ($tokencompare === $token) {
				$RESPONSE ['mensage'] = 'valid token';
				$RESPONSE ['valid'] = 'true';
				$RESPONSE ['expired'] = $newexpired;
				$RESPONSE ['token'] = self::createToken ( );
			} else {
				$RESPONSE ['mensage'] = 'invalid token';
				$RESPONSE ['valid'] = 'false';
				$RESPONSE ['rejected'] = $token;
				$RESPONSE ['expired'] = $newexpired;
				$RESPONSE ['token'] = self::createToken ( );
			}
		}
		
		return $RESPONSE;
	}
	
	/**
	 * Check password customized request whith registred password in your database system
	 *
	 * @param string $pwdRequest        	
	 * @param string $pwdRegistred        	
	 * @return array
	 */
	final public function checkPassword($pwdRequest, $pwdRegistred) {
		unset ( $RESPONSE );
		$buuumm = explode ( '$', $pwdRegistred );
		$mode = strtolower ( $buuumm [0] );
		$salt = $buuumm [1];
		$hash = $buuumm [2];
		
		if (self::hashModePwdCuston ( $mode, $salt, $pwdRequest ) === $pwdRegistred) {
			$RESPONSE ['password'] = 'true';
			$RESPONSE ['token'] = self::createToken ( $mode );
		} else {
			$RESPONSE ['password'] = 'false';
			$RESPONSE ['token'] = self::createToken ( $mode );
		}
		
		return $RESPONSE;
	}
}
