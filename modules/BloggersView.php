<?php
/** Web-Recon: Bloggers view (title, HTTP code, Alexa, Moz, social links, links) */
class BloggersView {
    private $client; private $config;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; $this->config=$config; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base = "$scheme://$target/";
        $r = $this->client ? $this->client->get($base) : ['body'=>'','code'=>0];
        $body = (string)($r['body'] ?? '');
        $title = null;
        if (preg_match('/<title[^>]*>(.*?)<\/title>/ims', $body, $m)) $title = trim(html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        $alexa = null;
        $x = @simplexml_load_file('http://data.alexa.com/data?cli=10&url=' . urlencode($target));
        if ($x && isset($x->SD->POPULARITY)) $alexa = (string)$x->SD->POPULARITY->attributes()->TEXT;
        $moz = ['note'=>'Moz API keys not configured'];
        $access = $this->config ? $this->config->get('moz_access_id') : null;
        $secret = $this->config ? $this->config->get('moz_secret_key') : null;
        if ($access && $secret) {
            $expires = time() + 300;
            $sig = urlencode(base64_encode(hash_hmac('sha1', $access . "\n" . $expires, $secret, true)));
            $url = 'http://lsapi.seomoz.com/linkscape/url-metrics/' . urlencode($target) . '?Cols=103079231492&AccessID=' . urlencode($access) . '&Expires=' . $expires . '&Signature=' . $sig;
            $rr = $this->client ? $this->client->get($url) : ['body'=>''];
            $j = json_decode((string)($rr['body'] ?? ''), true);
            if (is_array($j)) $moz = ['moz_rank'=>$j['umrp'] ?? null,'domain_authority'=>$j['pda'] ?? null,'page_authority'=>$j['upa'] ?? null];
        }
        $dom = new DOMDocument();
        @$dom->loadHTML($body);
        $links = $dom->getElementsByTagName('a');
        $social = ['facebook'=>[],'twitter'=>[],'instagram'=>[],'youtube'=>[],'github'=>[],'pinterest'=>[]];
        $linkCount = 0;
        foreach ($links as $a) {
            $href = $a->getAttribute('href');
            $linkCount++;
            foreach (array_keys($social) as $name) {
                $needle = $name === 'github' ? 'github.com/' : $name . '.com/';
                if (strpos($href, $needle) !== false) $social[$name][] = $href;
            }
        }
        $social = array_filter($social, fn($v) => $v !== []);
        return ['url'=>$base,'http_code'=>$r['code'] ?? 0,'title'=>$title,'alexa_rank'=>$alexa,'moz'=>$moz,'social_links'=>$social,'link_count'=>$linkCount];
    }
}
