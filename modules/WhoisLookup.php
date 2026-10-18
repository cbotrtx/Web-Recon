<?php
/** Web-Recon: WHOIS via RDAP (rdap.org) + system whois fallback */
class WhoisLookup {
    private $client; private $cache;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; $this->cache=$cache; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $key = "whois:$target";
        if ($this->cache && ($c=$this->cache->get($key))) return $c;
        $out = ['domain'=>$target];
        try {
            $r = $this->client ? $this->client->get("https://rdap.org/domain/".urlencode($target)) : ['body'=>'','code'=>0];
            if (($r['code']??0)===200 && ($j=json_decode($r['body'],true))) {
                $out['rdap_status'] = $j['status'] ?? [];
                $out['creation'] = $this->rdapEvent($j,'registration');
                $out['updated'] = $this->rdapEvent($j,'last changed');
                $out['expiry'] = $this->rdapEvent($j,'expiration');
                $out['registrar'] = $j['entities'][0]['vcardArray'][1] ?? null;
                $out['nameservers'] = array_column($j['nameservers']??[],'ldhName');
                $out['raw_events'] = $j['events'] ?? [];
            } else { $out['rdap'] = 'unavailable (code '.($r['code']??'?').')'; }
        } catch (Throwable $e) { $out['rdap_error']=$e->getMessage(); }
        // system whois fallback
        $w = trim((string)@shell_exec('whois '.escapeshellarg($target).' 2>/dev/null | head -n 60'));
        if ($w !== '') $out['whois_snippet'] = $w;
        if ($this->cache) $this->cache->set($key,$out);
        return $out;
    }
    private function rdapEvent(array $j, string $action): ?string {
        foreach ($j['events']??[] as $e) if (($e['eventAction']??'')===$action) return $e['eventDate']??null;
        return null;
    }
}
