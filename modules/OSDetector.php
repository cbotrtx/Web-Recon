<?php
/** Web-Recon: OS detection via passive fingerprinting (ICMP TTL, TCP banners, HTTP clues, open-port hints) */
class OSDetector {
    private $client; private $cache; private $logger;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; $this->cache=$cache; $this->logger=$logger; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $key = "os:$target";
        if ($this->cache && ($c=$this->cache->get($key))) return $c;
        $hostOnly = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $ip = filter_var($hostOnly, FILTER_VALIDATE_IP) ? $hostOnly : gethostbyname($hostOnly);
        $signals = [];
        $votes = [];
        $add = function(string $os, int $w, string $why) use (&$votes, &$signals) {
            $votes[$os] = ($votes[$os] ?? 0) + $w;
            $signals[] = "$why => $os (+$w)";
        };
        $out = ['target'=>$target,'ip'=>$ip];
        // 1) ICMP TTL (initial TTL 64=Linux/Unix, 128=Windows, 255=network gear/Solaris; degrades over hops)
        $ttl = $this->pingTTL($hostOnly);
        $out['icmp_ttl'] = $ttl;
        if ($ttl !== null) {
            if ($ttl <= 64) $add('Linux/Unix-like', 2, "ICMP TTL=$ttl (near 64)");
            elseif ($ttl <= 128) $add('Windows', 2, "ICMP TTL=$ttl (near 128)");
            else $add('Network appliance / Solaris / BSD family', 1, "ICMP TTL=$ttl (near 255)");
        } else {
            $signals[] = 'ICMP ping blocked or unavailable — TTL signal skipped';
        }
        // 2) TCP banner grabs on telling ports
        $grabs = $this->tcpGrab($ip, [22,25,110,143,445,3389,3306,5432], $depth==='1'?1.5:2.5);
        $out['tcp'] = ['probed'=>[22,25,110,143,445,3389,3306,5432],'responded'=>array_keys($grabs)];
        foreach ($grabs as $port=>$banner) {
            $b = strtolower((string)$banner);
            if ($port === 22 && $banner !== '') {
                if (str_contains($b,'openssh')) $add('Linux/Unix-like', 2, "SSH banner: $banner");
                elseif (str_contains($b,'microsoft')||str_contains($b,'windows')) $add('Windows', 3, "SSH banner: $banner");
                else $signals[] = "SSH banner: $banner";
            }
            if ($port === 3389) $add('Windows', 4, 'RDP port 3389 open');
            if ($port === 445) $add('Windows / Samba host', 2, 'SMB port 445 open');
            if ($port === 25 && $banner !== '') {
                if (str_contains($b,'microsoft')) $add('Windows', 2, "SMTP banner: $banner");
                else $signals[] = "SMTP banner: $banner";
            }
            if (str_contains($b,'ubuntu')||str_contains($b,'debian')||str_contains($b,'centos')||str_contains($b,'red hat')) $add('Linux', 2, "banner: $banner");
        }
        // 3) HTTP Server / Powered-By hints
        try {
            $r = $this->client ? $this->client->get("$scheme://$target/", [], true) : ['headers'=>[]];
            $h = array_change_key_case($r['headers'] ?? [], CASE_LOWER);
            $srv = $h['server'] ?? '';
            $out['http_server'] = $srv !== '' ? $srv : 'unknown';
            $s = strtolower($srv);
            if (str_contains($s,'microsoft-iis')||str_contains($s,'win32')||str_contains($s,'windows')) $add('Windows', 3, "HTTP Server: $srv");
            elseif (str_contains($s,'apache')||str_contains($s,'nginx')||str_contains($s,'openresty')||str_contains($s,'lighttpd')||str_contains($s,'envoy')) $add('Linux/Unix-like', 1, "HTTP Server: $srv (typically Linux-hosted)");
            elseif ($srv !== '' && !str_contains($s,'cloudflare') && !str_contains($s,'akamai') && !str_contains($s,'fastly')) $signals[] = "HTTP Server: $srv";
            else $signals[] = "HTTP Server hidden behind CDN/proxy ('$srv') — weak signal";
            if (!empty($h['x-powered-by'])) {
                $signals[] = 'X-Powered-By: ' . $h['x-powered-by'];
                if (stripos($h['x-powered-by'],'asp.net') !== false) $add('Windows', 2, 'X-Powered-By ASP.NET');
            }
        } catch (Throwable $e) { $out['http_error'] = $e->getMessage(); }
        arsort($votes);
        $total = array_sum($votes) ?: 1;
        $guesses = [];
        foreach ($votes as $os=>$w) $guesses[] = ['os'=>$os,'confidence'=>min(95,(int)round($w/$total*100))];
        if (!$guesses) $guesses[] = ['os'=>'Unknown (filtered / CDN-fronted — no distinctive signals)','confidence'=>0];
        $out['signals'] = $signals;
        $out['guesses'] = array_slice($guesses, 0, 4);
        $out['best_guess'] = $guesses[0]['os'];
        $out['disclaimer'] = 'Passive heuristics only: TTL degrades over hops and CDNs hide the origin. Confirm with authorized active fingerprinting.';
        // Don't cache "Unknown" — one signal-free run used to block re-probing for the whole TTL.
        if ($this->cache && !str_starts_with($out['best_guess'], 'Unknown')) $this->cache->set($key,$out);
        return $out;
    }
    private function pingTTL(string $host): ?int {
        $out = trim((string)@shell_exec('ping -c1 -W2 '.escapeshellarg($host).' 2>/dev/null'));
        if (preg_match('/ttl=(\d+)/i', $out, $m)) return (int)$m[1];
        return null;
    }
    private function tcpGrab(string $ip, array $ports, float $timeout): array {
        $res = [];
        $addr = function_exists('wr_socket_host') ? wr_socket_host($ip) : $ip;
        foreach ($ports as $p) {
            $s = @stream_socket_client("tcp://$addr:$p", $en, $es, $timeout, STREAM_CLIENT_CONNECT);
            if (!$s) continue;
            @stream_set_timeout($s, (int)max(1,$timeout));
            $d = @fread($s, 256);
            @fclose($s);
            $res[$p] = $d === false ? '' : trim((string)$d);
        }
        return $res;
    }
}
