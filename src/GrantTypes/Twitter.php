<?php
namespace Blimp\Accounts\GrantTypes;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Symfony\Component\HttpFoundation\Response;

use Blimp\Accounts\Oauth1\Protocol;

class Twitter {
    public function process(Container $api, $data, $redirect_uri = null) {
        if (array_key_exists('account', $data)) {
            $account = $data['account'];
        }
        if (array_key_exists('token', $data)) {
            $token = $data['token'];
        }
        if (array_key_exists('scope', $data)) {
            $scope = $data['scope'];
        }

        if (empty($account)) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_request';
          $this->error_description = 'Missing account parameter.';
          return false;
        }

        if (empty($token)) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_request';
          $this->error_description = 'Missing token parameter.';
          return false;
        }

        $owner = $api['security.oauth.get_resource_owner']($account, null);

        if ($owner === null) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_grant';
          $this->error_description = 'Invalid resource owner credentials.';
          return false;
        }

        $dm = $api['dataaccess.mongoodm.documentmanager']();

        $account = $dm->getRepository('Blimp\Accounts\Documents\Account')->find(substr($account, strrpos($account, '/') + 1));

        if ($account === null) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_grant';
          $this->error_description = 'Invalid resource owner credentials.';
          return false;
        }

        $access_token = $token['oauth_token'];
        $oauth_token_secret = $token['oauth_token_secret'];

        $key = Protocol::getNonceAndTimestamp();

        /* Get profile_data */
        $params = [
            'include_entities' => 'false',
            'skip_status' => 'true'
        ];

        $oauth_params = [
            'oauth_consumer_key' => $api['config']['twitter']['consumer_key'],
            'oauth_nonce' => $key['nonce'],
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => $key['timestamp'],
            'oauth_token' => $access_token,
            'oauth_version' => '1.0'
        ];

        $profile_data = Protocol::get('https://api.twitter.com/1.1/account/verify_credentials.json', $params, $oauth_params, $api['config']['twitter']['consumer_secret'], $oauth_token_secret);

        if($profile_data instanceof Response) {
            $this->error_code = Response::HTTP_BAD_REQUEST;
            $this->error = 'invalid_grant';
            $this->error_description = 'Invalid resource owner credentials.';
            return false;
        }

        if($profile_data['id'] !== $account->getProfileData()['id']) {
            $this->error_code = Response::HTTP_BAD_REQUEST;
            $this->error = 'invalid_grant';
            $this->error_description = 'Invalid resource owner credentials.';
            return false;
        }

        $this->profile = $owner->getProfile();

        if (!empty($scope)) {
          $to_process_scope = explode(' ', $scope);
        } else {
          $to_process_scope = [];
        }

        $user_scopes = $owner->getScopes();

        $this->real_scope = implode(' ', $api['security.oauth.get_scopes']($to_process_scope, $user_scopes));

        if (empty($this->real_scope) xor empty($user_scopes)) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_scope';
          $this->error_description = 'The requested scope is invalid, unknown or malformed.';

          return false;
        }

        return true;
    }

    public function canBePublic() {
        return false;
    }

    public function getProfile() {
        return $this->profile;
    }

    public function getScope() {
        return $this->real_scope;
    }

    public function getError() {
        if(empty($this->error_code)) {
            return null;
        }

        $error = new \stdClass();
        $error->error_code = $this->error_code;
        $error->error = $this->error;
        $error->error_description = $this->error_description;

        return $error;
    }
}
