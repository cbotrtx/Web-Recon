<?php
/** Web-Recon wordlist configuration */
return [
    'subdomains' => __DIR__ . '/../data/wordlists/subdomains.txt',
    'endpoints' => __DIR__ . '/../data/wordlists/endpoints.txt',
    'limits' => ['1' => 50, '2' => 300, '3' => 2000],
];
