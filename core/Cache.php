<?php
/**
 * Web-Recon: Simple file-based cache with TTL
 */
class Cache {
    private $dir;
    private $ttl;
    public function __construct(?string $dir = null, int $ttl = 3600) {
        $this->dir = $dir ?: (defined('WR_CACHE_DIR') ? WR_CACHE_DIR : __DIR__ . '/../cache');
        $this->ttl = $ttl;
        if (!is_dir($this->dir)) @mkdir($this->dir, 0755, true);
    }
    private function path(string $key): string { return $this->dir . '/' . sha1($key) . '.json'; }
    public function get(string $key) {
        $f = $this->path($key);
        if (!file_exists($f)) return null;
        if (time() - filemtime($f) > $this->ttl) { @unlink($f); return null; }
        $d = json_decode(@file_get_contents($f), true);
        return $d['value'] ?? null;
    }
    public function set(string $key, $value): void {
        @file_put_contents($this->path($key), json_encode(['value'=>$value,'ts'=>time()]));
    }
    public function clear(): void {
        foreach (glob($this->dir . '/*.json') ?: [] as $f) @unlink($f);
    }
}
