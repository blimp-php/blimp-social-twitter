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

    public function processAccountData(array $oauth_data) {
        if ($oauth_data != NULL && $oauth_data['oauth_token'] != NULL) {
            $access_token = $oauth_data['oauth_token'];
            $oauth_token_secret = $oauth_data['oauth_token_secret'];

            $key = Protocol::getNonceAndTimestamp();

            /* Get profile_data */
            $params = [
                'include_entities' => 'false',
                'skip_status' => 'false'
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
                $id = 'twitter-' . $profile_data['id'];
                $profile_url = 'https://www.twitter.com/' . $profile_data['screen_name'];
                $mug = $profile_data['profile_image_url_https'];

                $account = new Account();
                $account->setId($id);
                $account->setType('twitter');
                $account->setAuthData($oauth_data);
                $account->setProfileData($profile_data);

                $dm = $this->api['dataaccess.mongoodm.documentmanager']();

                $check = $dm->find('Blimp\Accounts\Documents\Account', $id);

                if ($check != null) {
                    // TODO
                    throw new BlimpHttpException(Response::HTTP_CONFLICT, "Duplicate Id", "Id strategy set to NONE and provided Id already exists");
                }

                $dm->persist($account);
                $dm->flush();

                $resource_uri = $this->request->getPathInfo() . '/' . $account->getId();

                $response = new JsonResponse((object) ["uri" => $resource_uri], Response::HTTP_CREATED);
                $response->headers->set('Location', $resource_uri);

                return $response;
            } else {
                throw new KRestException(KHTTPResponse::NOT_FOUND, KEXCEPTION_RESOURCE_NOT_FOUND, profile_data);
            }
        } else {
            throw new KRestException(KHTTPResponse::UNAUTHORIZED, KEXCEPTION_FACEBOOK_ACCESS_DENIED);
        }
    }
}
