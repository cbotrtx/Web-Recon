<?php
/** Web-Recon: Subdomain discovery — crt.sh, OTX, HackerTarget, Wayback + DNS brute-force */
class SubdomainEnumerator {
    private $client; private $cache; private $logger; private $config;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client;$this->cache=$cache;$this->logger=$logger;$this->config=$config; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $target = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $key = "subs:$target:$depth";
        if ($this->cache && ($c=$this->cache->get($key))) return $c;
        $found = [];
        $errors = [];
        $add = function(string $host, string $src, ?string $ip = null) use ($target, &$found) {
            $host = strtolower(trim($host, " \t*."));
            $t = strtolower($target);
            // Require a real subdomain boundary: "evil-example.com" ends with the
            // string "example.com" but is NOT a subdomain of it.
            if ($host === '' || ($host !== $t && !str_ends_with($host, '.' . $t))) return;
            if (!isset($found[$host])) $found[$host] = ['source'=>$src];
            elseif (strpos($found[$host]['source'], $src) === false) $found[$host]['source'] .= ",$src";
            if ($ip && empty($found[$host]['ip'])) $found[$host]['ip'] = $ip;
        };
        // 1) Certificate Transparency (crt.sh)
        try {
            $r = $this->client ? $this->client->get("https://crt.sh/?q=".urlencode('%'.$target)."&output=json") : ['body'=>''];
            $j = json_decode($r['body'] ?? '', true);
            if (is_array($j)) foreach ($j as $row) foreach (explode("\n", $row['name_value'] ?? '') as $n) $add($n, 'crt.sh');
        } catch (Throwable $e) { $errors['crt.sh'] = $e->getMessage(); }
        // 2) AlienVault OTX passive DNS (no key)
        try {
            $r = $this->client ? $this->client->get("https://otx.alienvault.com/api/v1/indicators/domain/".urlencode($target)."/passive_dns") : ['body'=>''];
            $j = json_decode($r['body'] ?? '', true);
            foreach (($j['passive_dns'] ?? []) as $rec) if (!empty($rec['hostname'])) $add($rec['hostname'], 'otx');
        } catch (Throwable $e) { /* optional source */ }
        // 3) HackerTarget hostsearch (free)
        try {
            $r = $this->client ? $this->client->get("https://api.hackertarget.com/hostsearch/?q=".urlencode($target)) : ['body'=>''];
            foreach (explode("\n", (string)($r['body'] ?? '')) as $line) {
                $parts = explode(',', trim($line));
                if (count($parts) === 2 && !str_starts_with(strtolower($parts[0]), 'error')) $add($parts[0], 'hackertarget', trim($parts[1]));
            }
        } catch (Throwable $e) { /* optional source */ }
        // 4) Wayback CDX wildcard hosts
        try {
            $r = $this->client ? $this->client->get("https://web.archive.org/cdx/search/cdx?url=*.".urlencode($target)."/*&output=json&fl=original&collapse=urlkey&limit=1500") : ['body'=>''];
            $j = json_decode($r['body'] ?? '', true);
            if (is_array($j)) {
                $n = 0;
                foreach (array_slice($j, 1) as $row) {
                    $h = parse_url(is_array($row) ? ($row[0] ?? '') : (string)$row, PHP_URL_HOST);
                    if ($h) { $add($h, 'wayback'); if (++$n > 400) break; }
                }
            }
        } catch (Throwable $e) { /* optional source */ }
        // 5) Wordlist DNS brute-force via DoH (bounded by depth)
        $limits = ['1'=>50,'2'=>300,'3'=>2000];
        $limit = $limits[$depth] ?? 300;
        $wl = $this->loadWordlist($limit);
        $chall = [];
        foreach (array_slice($wl, 0, $limit) as $w) { $h = "$w.$target"; if (!isset($found[$h])) $chall[] = $h; }
        $alive = $this->resolveMany($chall);
        foreach ($alive as $h=>$ip) $found[$h] = ['source'=>'bruteforce','ip'=>$ip];
        $subs = array_keys($found);
        $bySource = [];
        foreach ($subs as $s) foreach (explode(',', $found[$s]['source']) as $src) $bySource[$src] = ($bySource[$src] ?? 0) + 1;
        $out = ['domain'=>$target,'count'=>count($subs),'by_source'=>$bySource,'subdomains'=>$found,'wordlist_tried'=>min($limit,count($wl))];
        if ($errors) $out['source_errors'] = $errors;
        if ($this->cache) $this->cache->set($key,$out);
        return $out;
    }
    private function loadWordlist(int $limit): array {
        $f = __DIR__ . '/../data/wordlists/subdomains.txt';
        if (file_exists($f)) { $w = array_values(array_filter(array_map('trim', file($f, FILE_IGNORE_NEW_LINES)))); if ($w) return $w; }
        return explode(',', 'www,mail,ftp,admin,api,dev,test,staging,blog,shop,portal,m,mobile,secure,vpn,owa,exchange,webmail,ns1,ns2,smtp,pop,imap,cdn,static,assets,img,images,docs,help,support,beta,demo,app,apps,internal,git,ci,jenkins,jira,confluence,wiki,db,database,proxy,gateway,auth,sso,login,dashboard,panel,cpanel,whm,direct,origin,edge,cache,lb,monitor,status,devops,qa,uat,prod,legacy,old,new,v2,billing,pay,checkout,forum,community,news,events,careers,about,contact,home,main,default,server,host,cloud,storage,backup,mx,relay,gw,firewall,router,switch,voip,sip,crm,erp,hr,finance,legal,marketing,sales,ops,sec,lab,playground,sandbox');
    }
    private function resolveMany(array $hosts): array {
        $alive = [];
        foreach (array_chunk($hosts, 50) as $chunk) {
            $mh = curl_multi_init(); $hs = [];
            foreach ($chunk as $h) {
                $ch = curl_init("https://cloudflare-dns.com/dns-query?name=".urlencode($h)."&type=A");
                curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>6,CURLOPT_HTTPHEADER=>['accept: application/dns-json'],CURLOPT_SSL_VERIFYPEER=>false]);
                curl_multi_add_handle($mh,$ch); $hs[$h]=$ch;
            }
            $run = null; do { curl_multi_exec($mh,$run); curl_multi_select($mh,0.3); } while ($run > 0);
            foreach ($hs as $h=>$ch) {
                $j = json_decode((string)curl_multi_getcontent($ch), true);
                if (!empty($j['Answer'])) $alive[$h] = $j['Answer'][0]['data'] ?? 'resolved';
                curl_multi_remove_handle($mh,$ch);
            }
            curl_multi_close($mh);
        }
        return $alive;
    }
}
