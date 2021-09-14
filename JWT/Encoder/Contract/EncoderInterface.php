<?php

namespace JWT\Encoder\Contract;

use JWT\Entity\JWT;

interface EncoderInterface {
    public function decode(string $token): JWT;
    public function encode(array $header, array $payload): JWT;
    public function getAlgorithmCode(): string;
}
