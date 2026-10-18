<?php
/** Web-Recon: IP geolocation via ip-api.com (no key) */
class IPGeolocation {
    private $client; private $cache;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; $this->cache=$cache; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $ip = filter_var($target, FILTER_VALIDATE_IP) ? $target : gethostbyname($target);
        $key = "geo:$ip";
        if ($this->cache && ($c=$this->cache->get($key))) return $c;
        $out = ['ip'=>$ip,'hostname'=>@gethostbyaddr($ip)?:null];
        try {
            $r = $this->client ? $this->client->get("http://ip-api.com/json/".urlencode($ip)."?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query") : ['body'=>''];
            $j = json_decode($r['body']??'', true);
            if (($j['status']??'')==='success') $out = array_merge($out,$j);
            else $out['note'] = 'geolocation unavailable';
        } catch (Throwable $e) { $out['error']=$e->getMessage(); }
        if ($this->cache) $this->cache->set($key,$out);
        return $out;
    }
}
