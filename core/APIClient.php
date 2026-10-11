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
        if ($this->config && method_exists($this->config,'get')) return (string)$this->config->get('user_agent', WR_DEFAULT_UA);
        return WR_DEFAULT_UA;
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
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout());
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, min(10, $this->timeout()));
        curl_setopt($ch, CURLOPT_USERAGENT, $this->ua());
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        if (strtoupper($method) === 'HEAD') curl_setopt($ch, CURLOPT_NOBODY, true);
        if (strtoupper($method) === 'POST') { curl_setopt($ch, CURLOPT_POST, true); if ($body!==null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body); }
        if ($headers) curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        if ($this->proxy()) { curl_setopt($ch, CURLOPT_PROXY, $this->proxy()); }
        $respHeaders = [];
        if ($includeHeaders) {
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($ch, $h) use (&$respHeaders) {
                $len = strlen($h); $parts = explode(':', $h, 2);
                if (count($parts) === 2) $respHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                return $len;
            });
        }
        $body_out = curl_exec($ch);
        $info = curl_getinfo($ch);
        $err = curl_error($ch);
        return ['body' => $body_out === false ? '' : $body_out, 'headers' => $respHeaders, 'info' => $info, 'error' => $err, 'code' => $info['http_code'] ?? 0];
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
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
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
                $results[$u] = ['body'=>$body?:'', 'info'=>$info, 'code'=>$info['http_code']??0, 'error'=>curl_error($ch)];
                curl_multi_remove_handle($mh, $ch);
            }
            curl_multi_close($mh);
        }
        return $results;
    }
}
