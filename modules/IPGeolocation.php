<?php
/** Web-Recon: IP geolocation via ip-api.com (no key) */
class IPGeolocation {
    private $client; private $cache;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; $this->cache=$cache; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $host = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        $key = "geo:$ip";
        if ($this->cache && ($c=$this->cache->get($key))) return $c;
        $out = ['ip'=>$ip,'hostname'=>@gethostbyaddr($ip)?:null];
        $ok = false;
        try {
            $r = $this->client ? $this->client->get("http://ip-api.com/json/".urlencode($ip)."?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query") : ['body'=>''];
            $j = json_decode($r['body']??'', true);
            if (($j['status']??'')==='success') { $out = array_merge($out,$j); $ok = true; }
            else $out['note'] = 'geolocation unavailable';
        } catch (Throwable $e) { $out['error']=$e->getMessage(); }
        if ($this->cache && $ok) $this->cache->set($key,$out); // don't cache failures for the whole TTL
        return $out;
    }
}
