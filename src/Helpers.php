<?php
declare(strict_types=1);

namespace Coinbase;

use React\Http\Browser as Client;
use React\Http\Message\Response;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;

final class Helpers
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $passphrase;

    /**
     * @param Client $client
     * @param string $key
     * @param string $secret
     * @param string $passphrase
     */
    public function __construct(Client $client, string $key, string $secret, string $passphrase)
    {
        $this->client = $client;
        $this->key = $key;
        $this->secret = $secret;
        $this->passphrase = $passphrase;
    }

    /**
     * @param string $method The request method
     * @param string $path The request path
     * @param array|null $body The request body
     * @param int|null $timestamp The request timestamp
     * @return string The request signature
     */
    private function sign(string $method, string $path, array $body = null, int $timestamp = null): string
    {
        $body = is_null($body) ? '' : json_encode($body);
        $timestamp = is_null($timestamp) ? time() : $timestamp;
        $path = "/$path";

        $what = $timestamp . $method . $path . $body;

        $secret = base64_decode($this->secret, true);
        $hash = hash_hmac('sha256', $what, $secret, true);

        return base64_encode($hash);
    }

    /**
     * Build a path with an optional query string
     *
     * @param string $path The path
     * @param array|null $options The query args
     * @return string
     */
    public function withQuery(string $path, array $options = null): string
    {
        if (is_array($options) && count($options) > 0) {
            $path = sprintf('%s?%s', $path, http_build_query($options));
        }

        return $path;
    }

    /**
     * @param string $method The request method
     * @param string $path The request path
     * @param array|null $body The request body
     * @param int|null $timestamp The request timestamp
     * @return PromiseInterface
     */
    public function sendRequest(string $method, string $path, array $body = null, int $timestamp = null): PromiseInterface
    {
        $deferred = new Deferred();
        $timestamp = is_null($timestamp) ? time() : $timestamp;
        $headers = [
            'CB-ACCESS-KEY' => $this->key,
            'CB-ACCESS-SIGN' => $this->sign($method, $path, $body, $timestamp),
            'CB-ACCESS-TIMESTAMP' => $timestamp,
            'CB-ACCESS-PASSPHRASE' => $this->passphrase
        ];

        if (is_array($body)) {
            $rawBody = json_encode($body);
        } else {
            $rawBody = null;
        }

        $this->client->request($method, $path, $headers, $rawBody)
            ->then(function (Response $response) use ($deferred) {
                $body = $response->getBody()->getContents();
                $body = json_decode($body, true);
                $status = $response->getStatusCode();

                if (400 <= $status && $status <= 500) {
                    $message = $body['message'] ?? 'Unknown error';
                    $exception = 'Unknown';

                    switch ($status) {
                        case 400:
                            $exception = 'BadRequest';
                            break;
                        case 401:
                            $exception = 'Unauthorized';
                            break;
                        case 403:
                            $exception = 'Forbidden';
                            break;
                        case 404:
                            $exception = 'NotFound';
                            break;
                        case 500:
                            $exception = 'InternalServerError';
                            break;
                    }

                    $class = __NAMESPACE__ . '\\Exceptions\\' . $exception . 'Exception';
                    $deferred->reject(new $class($status, $message));
                } else {
                    $deferred->resolve($body);
                }
            }, function ($error) use ($deferred) {
                $deferred->reject($error);
            }, function ($p) use ($deferred) {
                $deferred->notify($p);
            });

        return $deferred->promise();
    }
}