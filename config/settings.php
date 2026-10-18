<?php
/** Web-Recon default settings (override via config/api_keys.php or env) */
return [
    'timeout' => 15,
    'user_agent' => 'Mozilla/5.0 (X11; Linux x86_64) Web-Recon/1.0 (Security Research)',
    'proxy' => null,
    'cache_ttl' => 3600,
    'depth' => '2',
    'shodan_api_key' => getenv('SHODAN_API_KEY') ?: '',
    'securitytrails_api_key' => getenv('SECURITYTRAILS_API_KEY') ?: '',
    'hibp_api_key' => getenv('HIBP_API_KEY') ?: '',
];
