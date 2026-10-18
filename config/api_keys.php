<?php
/** Web-Recon API keys — DO NOT COMMIT real keys. Prefer env vars. Copy from settings.php. */
return [
    'shodan_api_key' => getenv('SHODAN_API_KEY') ?: '',
    'securitytrails_api_key' => getenv('SECURITYTRAILS_API_KEY') ?: '',
    'hibp_api_key' => getenv('HIBP_API_KEY') ?: '',
    'whois_api_key' => getenv('WHOIS_API_KEY') ?: '',
];
