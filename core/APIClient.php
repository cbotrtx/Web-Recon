<?php
/**
 * Web-Recon: HTTP client (cURL wrapper) with proxy, caching hooks, multi-fetch
 */
class APIClient {
    private $config;
    private $logger;
    public function __construct($config = null, $logger = null) {
        $this->config = $config;
        $this->logger = $logger;
    }
    private function timeout(): int {
        if ($this->config && method_exists($this->config,'get')) return (int)$this->config->get('timeout', 15);
        return defined('WR_DEFAULT_TIMEOUT') ? WR_DEFAULT_TIMEOUT : 15;
    }
    private function ua(): string {
        $default = defined('WR_DEFAULT_UA') ? WR_DEFAULT_UA : 'Web-Recon/1.0';
        if ($this->config && method_exists($this->config,'get')) return (string)$this->config->get('user_agent', $default);
        return $default;
    }
    private function proxy(): ?string {
        if ($this->config && method_exists($this->config,'get')) return $this->config->get('proxy');
        return null;
    }
    public function get(string $url, array $headers = [], bool $includeHeaders = false): array {
        return $this->request('GET', $url, null, $headers, $includeHeaders);
    }
    public function head(string $url, array $headers = []): array {
        return $this->request('HEAD', $url, null, $headers, true);
    }
    public function request(string $method, string $url, $body = null, array $headers = [], bool $includeHeaders = false): array {
        $maxAttempts = 3;
        $result = null;
        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout());
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, min(10, $this->timeout()));
            curl_setopt($ch, CURLOPT_USERAGENT, $this->ua());
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
            $verifySsl = $this->config && method_exists($this->config,'get') ? (bool)$this->config->get('verify_ssl', false) : false;
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifySsl);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verifySsl ? 2 : 0);
            curl_setopt($ch, CURLOPT_ENCODING, '');
            if (strtoupper($method) === 'HEAD') curl_setopt($ch, CURLOPT_NOBODY, true);
            if (strtoupper($method) === 'POST') { curl_setopt($ch, CURLOPT_POST, true); if ($body!==null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body); }
            if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            if ($this->proxy()) { curl_setopt($ch, CURLOPT_PROXY, $this->proxy()); }
            $respHeaders = [];
            if ($includeHeaders) {
                curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $h) use (&$respHeaders) {
                    $len = strlen($h);
                    // A new status line starts a new response in a redirect chain:
                    // reset so redirect-only headers (Location, Set-Cookie, …) from
                    // an earlier hop don't leak into the final response's header set.
                    if (preg_match('#^HTTP/\S+\s+\d{3}#', trim($h))) { $respHeaders = []; return $len; }
                    $parts = explode(':', $h, 2);
                    if (count($parts) === 2) {
                        $name = strtolower(trim($parts[0]));
                        $value = trim($parts[1]);
                        if (isset($respHeaders[$name])) {
                            if (!is_array($respHeaders[$name])) $respHeaders[$name] = [$respHeaders[$name]];
                            $respHeaders[$name][] = $value;
                        } else {
                            $respHeaders[$name] = $value;
                        }
                    }
                    return $len;
                });
            }
            $body_out = curl_exec($ch);
            $info = curl_getinfo($ch);
            $err = curl_error($ch);
            $result = ['body' => $body_out === false ? '' : $body_out, 'headers' => $respHeaders, 'info' => $info, 'error' => $err, 'code' => $info['http_code'] ?? 0];
            if (($result['code'] ?? 0) !== 0 && $result['error'] === '') break;
            if ($attempt < $maxAttempts - 1) usleep(250000 * ($attempt + 1));
        }
        return $result;
    }
    /** Parallel GET for many URLs (curl_multi). Returns url => result array. */
    public function multiGet(array $urls, array $headers = [], int $concurrency = 20): array {
        $results = [];
        $chunks = array_chunk($urls, max(1,$concurrency));
        foreach ($chunks as $chunk) {
            $mh = curl_multi_init(); $handles = [];
            foreach ($chunk as $u) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $u);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout());
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, min(8, $this->timeout()));
                curl_setopt($ch, CURLOPT_USERAGENT, $this->ua());
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                $verifySsl = $this->config && method_exists($this->config,'get') ? (bool)$this->config->get('verify_ssl', false) : false;
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifySsl);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verifySsl ? 2 : 0);
                curl_setopt($ch, CURLOPT_ENCODING, '');
                if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                if ($this->proxy()) curl_setopt($ch, CURLOPT_PROXY, $this->proxy());
                curl_multi_add_handle($mh, $ch);
                $handles[$u] = $ch;
            }
            $running = null;
            do { curl_multi_exec($mh, $running); curl_multi_select($mh, 0.5); } while ($running > 0);
            foreach ($handles as $u => $ch) {
                $body = curl_multi_getcontent($ch);
                $info = curl_getinfo($ch);
                $res = ['body'=>$body?:'', 'info'=>$info, 'code'=>$info['http_code']??0, 'error'=>curl_error($ch)];
                if (($res['code'] ?? 0) === 0 || $res['error'] !== '') {
                    for ($retry = 0; $retry < 2; $retry++) {
                        usleep(200000 * ($retry + 1));
                        $r2 = $this->request('GET', $u, null, $headers, false);
                        if (($r2['code'] ?? 0) !== 0 && ($r2['error'] ?? '') === '') { $res = $r2; break; }
                    }
                }
                $results[$u] = $res;
                curl_multi_remove_handle($mh, $ch);
            }
            curl_multi_close($mh);
        }
        return $results;
    }
}
