<?php
/** Web-Recon: robots.txt scanner */
class RobotsScanner {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $url = "$scheme://$target/robots.txt";
        $r = $this->client ? $this->client->get($url) : ['body'=>'','code'=>0];
        $code = $r['code'] ?? 0;
        $body = (string)($r['body'] ?? '');
        $found = $code === 200 && trim($body) !== '';
        return ['url'=>$url,'http_code'=>$code,'found'=>$found,'content'=>$found ? $body : null,'note'=>$found ? 'robots.txt found' : 'robots.txt not found or empty'];
    }
}
