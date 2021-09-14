<?php

namespace JWT\Encoder;

use JWT\Encoder\Contract\EncoderInterface;
use JWT\Entity\JWT;
use JWT\Utils\SafeEncoder;

final class RS256 implements EncoderInterface {

    private string $privateKey;
    private string $publicKey;

    public function __construct(string $privateKey, string $publicKey) {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    public function decode(string $token): JWT {
        throw new NotImplementedException();
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
