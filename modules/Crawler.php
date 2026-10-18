<?php
/** Web-Recon: Sensitive file crawler */
class Crawler {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base = "$scheme://$target/";
        $files = ['admin.ini','backup.ini','others.ini'];
        $paths = [];
        foreach ($files as $f) {
            $p = __DIR__ . '/../crawl/' . $f;
            if (file_exists($p)) {
                foreach (explode(',', (string)file_get_contents($p)) as $x) {
                    $x = trim($x);
                    if ($x !== '') $paths[] = $x;
                }
            }
        }
        if (!$paths) $paths = ['admin','login','backup.zip','.env','config.php'];
        $paths = array_values(array_unique($paths));
        $limit = $depth === '1' ? 40 : ($depth === '2' ? 120 : 300);
        $paths = array_slice($paths, 0, $limit);
        $urls = array_map(fn($p) => $base . ltrim($p, '/'), $paths);
        $res = $this->client ? $this->client->multiGet($urls, [], 20) : [];
        $found = [];
        foreach ($res as $u => $r) {
            $code = $r['code'] ?? 0;
            if (in_array($code, [200, 201, 301, 302, 401, 403], true)) $found[] = ['url'=>$u,'code'=>$code];
        }
        return ['base'=>$base,'probed'=>count($urls),'found_count'=>count($found),'found'=>array_slice($found,0,100)];
    }
}
