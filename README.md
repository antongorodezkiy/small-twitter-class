small-twitter-class
===================

## Usage

```php

<?php

// Controller

class Socials extends Authorized_Controller
{
    private $twitter = null;
	public function __construct() {
		$config = array(
			'twitter_key' => 'twitter_key',
			'twitter_secret' => 'twitter_secret'
		);
		$this->twitter = new Twitter($config);
	}
	
	public function twitter_connect_start() {

		if ($this->twitter->getRequestToken()) {
			$addr = $this->twitter->getAuthorizeRedirectPath('http://example.com/twitter_connect_finish');

			redirect($addr);
		}
		else {
			die(_("Couldn't connect twitter account"));
		}
	}
	
	public function twitter_connect_finish() {
            
		if (isset($_GET['oauth_token'])) {
			$this->twitter->receiveVerifier(array(
				'oauth_token' => $_GET['oauth_token'],
				'oauth_verifier' => $_GET['oauth_verifier'],
			));
			
			$token = $this->twitter->getAccessToken();

			print_r($token);
			
		}
		else {
			die(_("Couldn't connect Twitter account"));
		}
	}
	

	public function share() {
		$result = $twitter->tweet('message', '/full/path/to/image.png', 'account_access_token', 'access_token_secret');
		 
		// or
			$config = array(
				'twitter_key' => 'twitter_key',
				'twitter_secret' => 'twitter_secret',
				'access_token' => 'account_access_token',
				'access_token_secret' => 'access_token_secret'
			);
			$twitter = new Twitter($config);
			
			// twitter access are valid
				if ( ! $this->twitter->check_permission('account_access_token') ) {
					die(_('Twitter account access expired or revoked, please reconnect it'));
				}
			
			$result = $this->twitter->tweet('message');
			
			if ($result) {
				die(_('Message was published on Twitter'));
			}
			else {
				die(_('Error publishing on Twitter'));
			} 
	}
		
}

```
