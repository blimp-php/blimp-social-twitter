<?php
namespace Blimp\Accounts\Rest;

use Blimp\Accounts\Documents\Account;
use Blimp\Http\BlimpHttpException;
use Blimp\Accounts\Oauth1\Oauth1AccessToken;
use Blimp\Accounts\Oauth1\Protocol;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class TwitterAccessToken extends Oauth1AccessToken {
    public function getRequestTokenEndpoint() {
        return 'https://api.twitter.com/oauth/request_token';
    }

    public function getAuthenticateEndpoint() {
        return 'https://api.twitter.com/oauth/authenticate';
    }

    public function getRequestAccessTokenEndpoint() {
        return 'https://api.twitter.com/oauth/access_token';
    }

    public function getConsumerKey() {
        return $this->api['config']['twitter']['consumer_key'];
    }

    public function getConsumerSecret() {
        return $this->api['config']['twitter']['consumer_secret'];
    }

    public function processAccountData($oauth_data) {
        if (!empty($oauth_data) && !empty($oauth_data['oauth_token']) && !empty($oauth_data['oauth_token_secret'])) {
            $access_token = $oauth_data['oauth_token'];
            $oauth_token_secret = $oauth_data['oauth_token_secret'];

            $key = Protocol::getNonceAndTimestamp();

            /* Get profile_data */
            $params = [
                'include_entities' => 'false',
                'skip_status' => 'true'
            ];

            $oauth_params = [
                'oauth_consumer_key' => $this->getConsumerKey(),
                'oauth_nonce' => $key['nonce'],
                'oauth_signature_method' => 'HMAC-SHA1',
                'oauth_timestamp' => $key['timestamp'],
                'oauth_token' => $access_token,
                'oauth_version' => '1.0'
            ];

            $profile_data = Protocol::get('https://api.twitter.com/1.1/account/verify_credentials.json', $params, $oauth_params, $this->getConsumerSecret(), $oauth_token_secret);

            if($profile_data instanceof Response) {
                return $profile_data;
            }

            if ($profile_data != null && $profile_data['id'] != null) {
                $id = hash_hmac('ripemd160', 'twitter-' . $profile_data['id'], 'obscure');

                $dm = $this->api['dataaccess.mongoodm.documentmanager']();

                $account = $dm->find('Blimp\Accounts\Documents\Account', $id);

                if ($account != null) {
                    $code = Response::HTTP_FOUND;
                } else {
                    $code = Response::HTTP_CREATED;

                    $account = new Account();
                    $account->setId($id);
                    $account->setType('twitter');
                }

                $resource_uri = '/accounts/' . $account->getId();

                $secret = NULL;
                if($account->getOwner() == NULL) {
                    $bytes = openssl_random_pseudo_bytes(16);
                    $hex   = bin2hex($bytes);
                    $secret = password_hash($hex, PASSWORD_DEFAULT);
                }

                $account->setBlimpSecret($secret);

                $account->setAuthData($oauth_data);
                $account->setProfileData($profile_data);

                $dm->persist($account);
                $dm->flush();

                $response = new JsonResponse((object) ["uri" => $resource_uri, "secret" => $secret], $code);
                $response->headers->set('AccountUri', $resource_uri);
                $response->headers->set('AccountSecret', $secret);

                return $response;
            } else {
                throw new BlimpHttpException(Response::HTTP_NOT_FOUND, 'Profile not found', $profile_data);
            }
        } else {
            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'Invalid credentials', $oauth_data);
        }
    }
}
