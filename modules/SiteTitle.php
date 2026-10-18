<?php
/** Web-Recon: Site title extraction */
class SiteTitle {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $url = "$scheme://$target/";
        $r = $this->client ? $this->client->get($url) : ['body'=>'','code'=>0];
        $body = (string)($r['body'] ?? '');
        $title = null;
        if (preg_match('/<title[^>]*>(.*?)<\/title>/ims', $body, $m)) $title = trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        return ['url'=>$url,'http_code'=>$r['code']??0,'title'=>$title];
    }
}
