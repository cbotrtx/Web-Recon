<?php
/**
 * Web-Recon: Runtime configuration holder
 */
class WR_Config {
    private $data = [];
    public function __construct(array $overrides = []) {
        $defaults = [];
        $settingsFile = __DIR__ . '/../config/settings.php';
        if (file_exists($settingsFile)) {
            $s = include $settingsFile;
            if (is_array($s)) $defaults = $s;
        }
        $this->data = array_merge([
            'timeout' => defined('WR_DEFAULT_TIMEOUT') ? WR_DEFAULT_TIMEOUT : 15,
            'user_agent' => defined('WR_DEFAULT_UA') ? WR_DEFAULT_UA : 'Web-Recon/1.0',
            'proxy' => null,
            'verify_ssl' => false,
            'follow_redirects' => true,
            'cache_ttl' => 3600,
            'depth' => '2',
        ], $defaults, $overrides);
        // Env overrides for API keys
        foreach (['SHODAN_API_KEY','SECURITYTRAILS_API_KEY','WHOIS_API_KEY'] as $k) {
            $v = getenv($k);
            if ($v) $this->data[strtolower($k)] = $v;
        }
    }
    public function get(string $key, $default = null) { return $this->data[$key] ?? $default; }
    public function set(string $key, $value): void { $this->data[$key] = $value; }
    public function all(): array { return $this->data; }
}
