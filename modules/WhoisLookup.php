<?php
/** Web-Recon: WHOIS via RDAP (rdap.org) + system whois fallback */
class WhoisLookup {
    private $client; private $cache;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; $this->cache=$cache; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $target = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        if (filter_var($target, FILTER_VALIDATE_IP)) return ['domain'=>$target,'note'=>'target is an IP address — no domain WHOIS/RDAP record'];
        // WHOIS/RDAP only know registrable domains — querying a subdomain
        // returns "Malformed request". Reduce scanme.nmap.org -> nmap.org first.
        $registered = $this->registrableDomain($target);
        $key = "whois:$registered";
        if ($this->cache && ($c=$this->cache->get($key))) return $c;
        $out = ['domain'=>$target, 'queried_domain'=>$registered];
        if ($registered !== $target) {
            $out['note'] = "queried registrable domain $registered — subdomains have no WHOIS/RDAP record of their own";
        }
        $rdapOk = false;
        try {
            $r = $this->client ? $this->client->get("https://rdap.org/domain/".urlencode($registered)) : ['body'=>'','code'=>0];
            if (($r['code']??0)===200 && ($j=json_decode($r['body'],true))) {
                $rdapOk = true;
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
        $w = trim((string)@shell_exec('whois '.escapeshellarg($registered).' 2>/dev/null | head -n 60'));
        if ($w !== '') $out['whois_snippet'] = $w;
        // Only cache real answers — caching a transient RDAP failure served the
        // "unavailable" result for the whole TTL even after the service recovered.
        if ($this->cache && ($rdapOk || $w !== '')) $this->cache->set($key,$out);
        return $out;
    }
    /**
     * Reduce a hostname to its registrable domain: scanme.nmap.org -> nmap.org.
     * Uses a compact two-level public-suffix list; anything not listed falls
     * back to the last two labels. Not a full PSL — multi-level registries
     * outside the list (e.g. *.blogspot.com) reduce to their last two labels.
     */
    private function registrableDomain(string $host): string {
        $host = strtolower(rtrim($host, '.'));
        if (filter_var($host, FILTER_VALIDATE_IP) || strpos($host, '.') === false) return $host;
        $labels = explode('.', $host);
        $n = count($labels);
        $twoLevel = ['co.uk','org.uk','ac.uk','gov.uk','me.uk','net.uk','sch.uk',
            'co.in','net.in','org.in','ac.in','gov.in','res.in','edu.in','firm.in','gen.in','ind.in',
            'co.jp','or.jp','ne.jp','ac.jp','go.jp','ed.jp',
            'com.au','net.au','org.au','edu.au','gov.au','asn.au','id.au',
            'co.nz','org.nz','net.nz','govt.nz','ac.nz','geek.nz','gen.nz',
            'com.br','net.br','org.br','gov.br','edu.br',
            'com.cn','net.cn','org.cn','gov.cn','edu.cn',
            'co.za','org.za','net.za','gov.za','ac.za',
            'com.mx','org.mx','net.mx','gob.mx','edu.mx',
            'co.kr','or.kr','ne.kr','go.kr','ac.kr','re.kr',
            'com.tr','net.tr','org.tr','gov.tr','edu.tr',
            'com.sg','net.sg','org.sg','gov.sg','edu.sg',
            'com.hk','net.hk','org.hk','gov.hk','edu.hk'];
        $last2 = $labels[$n-2] . '.' . $labels[$n-1];
        if ($n >= 3 && in_array($last2, $twoLevel, true)) return $labels[$n-3] . '.' . $last2;
        return $last2;
    }
    private function rdapEvent(array $j, string $action): ?string {
        foreach ($j['events']??[] as $e) if (($e['eventAction']??'')===$action) return $e['eventDate']??null;
        return null;
    }
}
