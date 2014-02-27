<?php 
/**
 * Small Twitter class
 *
 * @author Eduard Kozachek <antongorodezkiy@gmail.com>
 * @package Twitter
 * License: GNU/GPL 2
 */

class Twitter {
	
	public $responseData = array();
	public $responseDataRaw = null;
	public $responseInfo = null;
    private $errors = null;


    protected static $url = array(
		'request_token' => 'https://api.twitter.com/oauth/request_token',
		'authorize' => 'https://api.twitter.com/oauth/authorize',
		'access_token' => 'https://api.twitter.com/oauth/access_token',
		'verify_credentials' => 'https://api.twitter.com/1.1/account/verify_credentials.json',
		'update_profile' => 'https://api.twitter.com/1.1/account/update_profile.json',
		'update_profile_image' => 'https://api.twitter.com/1.1/account/update_profile_image.json',
		'status_update' => 'https://api.twitter.com/1.1/statuses/update.json',
		'status_update_with_media' => 'https://api.twitter.com/1.1/statuses/update_with_media.json',
		'account_settings' => 'https://api.twitter.com/1.1/account/settings.json'
	);
	
	protected $headers = array();
	protected $params = array();
	protected $data_params = array();
	protected $config = array();
	protected $token = array('oauth_token' => '', 'oauth_token_secret' => '');
	
	public function __construct($config = array()) {
		
		$this->config = $config;
		
		$this->initParams();
		
		if (isset($config['access_token'])) {
			$this->token = array(
				'oauth_token' => $config['access_token'],
				'oauth_token_secret' => $config['access_token_secret']
			);
		}
                
	}
	
	private function initParams() {
		$this->params = array(
			'oauth_consumer_key' => $this->config['twitter_key'],
			'oauth_nonce' => md5(time()+mt_rand(1,100)),
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => time(),
			'oauth_version' => '1.0'
		);
	}
	
	// (c) http://stackoverflow.com/questions/3295466/another-twitter-oauth-curl-access-token-request-that-fails/3327391#3327391
	static function urlencode($input)
    {
        if (is_array($input)) {
            return array_map(array(__CLASS__, 'urlencode'), $input);
        }
        else if (is_scalar($input)) {
            return str_replace('+',' ',str_replace('%7E', '~', rawurlencode($input)));
        }
        else{
            return '';
        }
    }
	
	public function makeSignature($url, $method = 'GET'){

		ksort($this->params);

		$request = $method.'&'.self::urlencode( $url ).'&'.self::urlencode(self::buildRequest( $this->params ));
		
		$secret = self::urlencode($this->config['twitter_secret']).'&'.( isset($this->token['oauth_token_secret']) ? self::urlencode($this->token['oauth_token_secret']) : '');

		$sign = self::urlencode(base64_encode( hash_hmac( 'sha1', $request, $secret, true ) ));

		return ($sign);
	}
	
	
	public static function buildRequest($params, $div = '&')
	{
		foreach($params as $key => $val)
			$requestString[] = $key.'='.$val;
		
		return implode($div,$requestString);
	}
	
	
	public static function buildHeader($params)
	{
		foreach($params as $key => $val)
			$requestString[] = $key.'="'.$val.'"';
		
		return 'Authorization: OAuth '.implode(', ',$requestString);
	}
	
	public function addHeader($header) {
		$this->headers[] = $header;
	}
	
	public function addHeaders($params) {
		$this->headers = $params;
	}
	
	public function addParam($name, $param) {
		$this->params[$name] = $param;
	}
	
	public function addParams($params) {
		$this->params = $params;
	}
	
	protected function get($url)
	{
		$curl = curl_init();
		  
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($curl, CURLOPT_TIMEOUT, 30);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLINFO_HEADER_OUT, true);
		
		curl_setopt($curl, CURLOPT_HTTPHEADER, array(self::buildHeader($this->params)));

		$this->responseDataRaw = curl_exec($curl);
		$this->responseData = json_decode($this->responseDataRaw, true);

		$this->responseInfo = curl_getinfo($curl);

		$isOk = (curl_getinfo($curl, CURLINFO_HTTP_CODE) == 200);
		
		curl_close($curl);
		
		if (!$isOk) {
			$this->errors = $this->responseData['errors'];
			Logger::i()->log_twitter('error',$this->errors);
			Logger::i()->log_twitter('error',$this->responseInfo);
			Logger::i()->log_twitter('error',$this->responseDataRaw);
		}
		else{
			$this->errors = null;
		}
		
		return $isOk;
	}
	
	protected function post($url, $data = array())
	{
                    
		$curl = curl_init();
		  
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($curl, CURLOPT_TIMEOUT, 30);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLINFO_HEADER_OUT, true);
		//curl_setopt($curl, CURLOPT_HEADER, true);
		
		curl_setopt($curl, CURLOPT_HTTPHEADER, array(self::buildHeader($this->params)));
		
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

		$this->responseDataRaw = curl_exec($curl);
		$this->responseData = json_decode($this->responseDataRaw, true);

		$this->responseInfo = curl_getinfo($curl);

		$isOk = (curl_getinfo($curl, CURLINFO_HTTP_CODE) == 200);
		
		curl_close($curl);                       
		
		if (!$isOk) {
			$this->errors = $this->responseData['errors'];
			Logger::i()->log_twitter('error',$this->errors);
			Logger::i()->log_twitter('error',$this->responseInfo);
			Logger::i()->log_twitter('error',$this->responseDataRaw);
		}
		else{
			$this->errors = null;
		}
		
		return $isOk;
	}
	
	
	/* Interface */
	
		// 1 step
		public function getRequestToken() {
			
			$this->params['oauth_signature'] = self::makeSignature(self::$url['request_token']);
			
			$result = $this->get(self::$url['request_token']);
			parse_str($this->responseDataRaw, $this->token);
			
			return $result;
		}
	
		// 2 step
		public function getAuthorizeRedirectPath($callback) {
			return self::$url['authorize'].'?'
					.self::buildRequest(array(
						'oauth_token' => $this->token['oauth_token'],
						'oauth_callback' => self::urlencode($callback),
						//'oauth_signature' => self::makeSignature()
					));
		}
	
		// 3 step
		public function receiveVerifier($token) {
			$this->token = array_merge($this->token,$token);
		}
		
		// 4 step
		public function getAccessToken() {
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['access_token'], 'POST');
			
			$this->params['oauth_verifier'] = $this->token['oauth_verifier'];

			$result = $this->post(self::$url['access_token']);

			parse_str($this->responseDataRaw, $this->token);

			return $this->token;
		}
                
		protected function setAccessToken($oauth_token = '', $oauth_token_secret = ''){
			$this->token['oauth_token'] = $oauth_token;
			$this->token['oauth_token_secret'] = $oauth_token_secret;
		}


		public function verify() {
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['verify_credentials']);

			$result = $this->get(self::$url['verify_credentials']);

			return $result;
		}
		
		public function check_permission() {
			return $this->getSettings();
		}
		
		public function getSettings() {
			$this->initParams();
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['account_settings']);

			$result = $this->get(self::$url['account_settings']);

			return $result;
		}
		
		public function getProfile() {
			$this->initParams();
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['verify_credentials']);

			$result = $this->get(self::$url['verify_credentials']);

			return $result;
		}
		
		
		public function updateProfile($data) {
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['update_profile'], 'POST');

			$result = $this->post(self::$url['update_profile'], $data);

			return $result;
		}


		public function updateAvatar($filename) {
			
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['update_profile_image'],'POST');
			
			$params['image'] = '@'.$filename;
			$result = $this->post(self::$url['update_profile_image'], $params);

			return $result;
		}
		
		public function tweet($message, $image = '', $oauth_token = '', $oauth_token_secret = '') {
                        
			if($oauth_token && $oauth_token_secret)
			{
				$this->setAccessToken($oauth_token, $oauth_token_secret);
			}
                    
			if ($image) {
				return $this->statusUpdateWithImage($message, $image);
			}
			else {
				return $this->statusUpdate($message);
			}
		}
		
		public function statusUpdate($message) {
			$this->initParams();
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['status_update'], 'POST');

			$data['status'] = $message;
			$result = $this->post(self::$url['status_update'], $data);

			if($this->errors){
				return false;
			}
			
			return $result;
		}
		
		
		public function statusUpdateWithImage($message, $image) {
			$this->initParams();
			$this->params['oauth_token'] = $this->token['oauth_token'];
			$this->params['oauth_signature'] = self::makeSignature(self::$url['status_update_with_media'], 'POST');

			$data['status'] = $message;
			$data['media'] = '@'.FCPATH.parse_url($image,PHP_URL_PATH);
			
			$result = $this->post(self::$url['status_update_with_media'], $data);
			
			if($this->errors){
				return false;
			}
			
			return $result;
		}

}

