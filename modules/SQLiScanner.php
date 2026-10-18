<?php
/** Web-Recon: Error-based SQLi scanner */
class SQLiScanner {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base = "$scheme://$target/";
        $r = $this->client ? $this->client->get($base) : ['body'=>''];
        $body = (string)($r['body'] ?? '');
        $dom = new DOMDocument();
        @$dom->loadHTML($body);
        $links = $dom->getElementsByTagName('a');
        $errors = file_exists(__DIR__ . '/../data/sqlerrors.ini') ? array_map('trim', explode(',', (string)file_get_contents(__DIR__ . '/../data/sqlerrors.ini'))) : [];
        if (!$errors) $errors = ['SQL syntax','mysql_fetch','ORA-','PostgreSQL','SQLite'];
        $tested = 0; $vulnerable = [];
        foreach ($links as $link) {
            $href = $link->getAttribute('href');
            if (strpos($href, '?') === false) continue;
            if ($tested >= ($depth === '1' ? 10 : 30)) break;
            $tested++;
            $url = strpos($href, '://') !== false ? $href . "'" : $base . ltrim($href, '/') . "'";
            $rr = $this->client ? $this->client->get($url) : ['body'=>''];
            $b = (string)($rr['body'] ?? '');
            foreach ($errors as $e) {
                if ($e !== '' && stripos($b, $e) !== false) { $vulnerable[] = ['url'=>$url,'error'=>$e]; break; }
            }
        }
        return ['base'=>$base,'tested'=>$tested,'vulnerable_count'=>count($vulnerable),'vulnerable'=>$vulnerable];
    }
}
