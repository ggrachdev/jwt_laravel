<?php

namespace JWT\Encoder;

use JWT\Encoder\Contract\EncoderInterface;
use JWT\Entity\JWT;
use JWT\Utils\SafeEncoder;

final class HS256 implements EncoderInterface {

    private string $privateKey;

    public function __construct(string $privateKey) {
        $this->privateKey = $privateKey;
    }

    public function decode(string $jwt): JWT {
        $tks = \explode('.', $jwt);

        if (\count($tks) != 3) {
            throw new \Exception('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;
        
        if (null === ($header = SafeEncoder::decodeJson(SafeEncoder::decodeBase64($headb64)))) {
            throw new \Exception('Invalid header encoding');
        }
        if (null === $payload = SafeEncoder::decodeJson(SafeEncoder::decodeBase64($bodyb64))) {
            throw new \Exception('Invalid claims encoding');
        }
        if (false === ($sig = SafeEncoder::decodeBase64($cryptob64))) {
            throw new \Exception('Invalid signature encoding');
        }

        $segments = [];
        $segments[] = \base64_encode(
            SafeEncoder::encodeJson($header)
        );
        $segments[] = SafeEncoder::encodeBase64(
                SafeEncoder::encodeJson($payload)
        );
        $signing_input = \implode('.', $segments);

        $signature = $this->sign($signing_input);
        $segments[] = $signature;
        $token = \implode('.', $segments);

        $jwt = new JWT($header, $payload, $signature, $token);
        
        return $jwt;
    }

    public function encode(array $header, array $payload): JWT {

        $segments = [];
        $segments[] = \base64_encode(
            SafeEncoder::encodeJson($header)
        );
        $segments[] = SafeEncoder::encodeBase64(
                SafeEncoder::encodeJson($payload)
        );
        $signing_input = \implode('.', $segments);

        $signature = $this->sign($signing_input);
        $segments[] = $signature;
        $token = \implode('.', $segments);

        $jwt = new JWT($header, $payload, $signature, $token);

        return $jwt;
    }

    private function sign($input) {
        $key = $this->privateKey;
        return \hash_hmac('SHA256', $input, $key, true);
    }

    public function getAlgorithmCode(): string {
        return 'HS256';
    }

}
