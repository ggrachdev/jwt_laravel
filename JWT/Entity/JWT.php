<?php

namespace JWT\Entity;

final class JWT {

    private $header;
    private $payload;
    private $signature;
    private $token;

    public function __construct($header, $payload, $signature, $token) {
        $this->header = $header;
        $this->payload = $payload;
        $this->signature = $signature;
        $this->token = $token;
    }

    public function getHeader() {
        return $this->header;
    }

    public function getPayload() {
        return $this->payload;
    }

    public function getSignature() {
        return $this->signature;
    }

    public function getToken() {
        return $this->token;
    }

}
