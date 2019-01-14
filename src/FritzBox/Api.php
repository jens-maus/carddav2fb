<?php

namespace Andig\FritzBox;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use Ringcentral\Psr7;

/**
 * Copyright (c) 2019 Andreas Götz
 * @license MIT
 */
class Api
{
    private $username;
    private $password;
    private $url;

    protected $sid = '0000000000000000';

    /**
     * Do not use this directly! Rather use {@see getClient()}
     *
     * @var Client
     */
    private $client;

    /**
     * Execute fb login
     *
     * @access public
     */
    public function __construct($url = 'https://fritz.box', $username = false, $password = false)
    {
        // set FRITZ!Box-IP and URL
        $this->url = $url;
        $this->username = $username;
        $this->password = $password;

        $this->initSID();
    }

    /**
     * Get initialized HTTP client
     *
     * @return Client
     */
    private function getClient(): Client
    {
        if (!$this->client) {
            $this->client = new Client($this->getClientOptions());
        }

        return $this->client;
    }

    /**
     * HTTP client options
     *
     * @param array $options
     * @return array
     */
    private function getClientOptions($options = []): array
    {
        return $options;
    }

    public function postFile(array $formFields, array $fileFields)
    {
        $multipart = [];

        // sid must be first parameter
        $formFields = array_merge(array('sid' => $this->sid), $formFields);

        foreach ($formFields as $key => $val) {
            $multipart[] = [
                'name' => $key,
                'contents' => $val,
            ];
        }

        foreach ($fileFields as $name => $file) {
            $multipart[] = [
                'name' => $name,
                'filename' => $file['filename'],
                'contents' => $file['content'],
                'headers' => [
                    'Content-Type' => $file['type'],
                ],
            ];
        }

        $url = rtrim($this->url, '/') . '/cgi-bin/firmwarecfg';
        $resp = $this->getClient()->request('POST', $url, [
            'multipart' => $multipart,
        ]);

        if (200 !== $resp->getStatusCode()) {
            throw new \Exception('Received HTTP ' . $resp->getStatusCode());
        }

        return (string)$resp->getBody();
    }

    /**
     * the login method, handles the secured login-process
     * newer firmwares (xx.04.74 and newer) need a challenge-response mechanism to prevent Cross-Site Request Forgery attacks
     * see http://www.avm.de/de/Extern/Technical_Note_Session_ID.pdf for details
     *
     * @return bool success
     */
    protected function initSID()
    {
        $loginpage = '/login_sid.lua';
        $url = rtrim($this->url, '/') . $loginpage;

        // read the current status
        $resp = $this->getClient()->request('GET', $url);
        if (200 !== $resp->getStatusCode()) {
            throw new \Exception('Received HTTP ' . $resp->getStatusCode());
        }

        // process response
        $xml = simplexml_load_string((string)$resp->getBody());
        if ($xml->SID != '0000000000000000') {
            $this->sid = (string)$xml->SID;
            return true;
        }

        // the challenge-response magic, pay attention to the mb_convert_encoding()
        $response = $xml->Challenge . '-' . md5(mb_convert_encoding($xml->Challenge . '-' . $this->password, "UCS-2LE", "UTF-8"));

        // login
        $resp = $this->getClient()->request('GET', $url, [
            'query' => [
                'username' => $this->username,
                'response' => $response,
            ]
        ]);
        if (200 !== $resp->getStatusCode()) {
            throw new \Exception('Received HTTP ' . $resp->getStatusCode());
        }

        // finger out the SID from the response
        $xml = simplexml_load_string((string)$resp->getBody());
        if ($xml->SID != '0000000000000000') {
            $this->sid = (string)$xml->SID;
            return true;
        }

        throw new \Exception('ERROR: Login failed with an unknown response.');
    }

    /**
     * a getter for the session ID
     *
     * @return string                $this->sid
     */
    public function getSID()
    {
        return $this->sid;
    }
}
