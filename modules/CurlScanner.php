<?php
/** Web-Recon: curl-style deep HTTP inspection — redirect chain, timing breakdown, method enumeration */
class CurlScanner {
    public function __construct($client=null,$cache=null,$logger=null,$config=null){}
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base = "$scheme://$target/";
        $chain = $this->redirectChain($base, 10);
        $final = $chain ? $chain[count($chain)-1]['url'] : $base;
        $out = [
            'base' => $base,
            'redirect_chain' => $chain,
            'redirect_count' => max(0, count($chain)-1),
            'final_url' => $final,
            'https_downgrade' => $this->downgrade($chain, $scheme),
        ];
        $out['timing'] = $this->timing($final);
        $out['methods'] = $this->methods($final);
        $risky = [];
        foreach ($out['methods'] as $m=>$info) {
            $code = $info['code'] ?? 0;
            if (in_array($m, ['PUT','DELETE','TRACE','PATCH'], true) && $code >= 200 && $code < 400) $risky[] = "$m ($code)";
        }
        $out['risky_methods_accepted'] = $risky;
        $out['note'] = $risky ? 'Review accepted methods — TRACE/PUT/DELETE can aid XSS, file overwrite or data tampering.' : 'No risky HTTP methods accepted on the probed URL.';
        return $out;
    }
    private function newHandle(string $url, int $timeout = 10) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(8, $timeout),
            CURLOPT_USERAGENT => defined('WR_DEFAULT_UA') ? WR_DEFAULT_UA : 'Web-Recon/1.0',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_ENCODING => '',
        ]);
        return $ch;
    }
    private function redirectChain(string $url, int $max): array {
        $chain = []; $seen = [];
        for ($i = 0; $i < $max; $i++) {
            if (isset($seen[$url])) { $chain[] = ['url'=>$url,'note'=>'redirect loop detected']; break; }
            $seen[$url] = true;
            $ch = $this->newHandle($url);
            curl_setopt($ch, CURLOPT_NOBODY, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            $raw = (string)curl_exec($ch);
            $info = curl_getinfo($ch);
            $code = $info['http_code'] ?? 0;
            if ($code === 0) { $chain[] = ['url'=>$url,'error'=>curl_error($ch) ?: 'connection failed']; break; }
            $step = ['url'=>$url,'code'=>$code];
            $srv = $this->headerVal($raw, 'server');
            if ($srv) $step['server'] = $srv;
            $loc = $info['redirect_url'] ?? '';
            if ($loc !== '') $step['location'] = $loc;
            $chain[] = $step;
            if ($code >= 300 && $code < 400 && $loc !== '') { $url = $this->resolve($url, $loc); continue; }
            break;
        }
        return $chain;
    }
    private function resolve(string $base, string $loc): string {
        if (preg_match('#^https?://#i', $loc)) return $loc;
        if (str_starts_with($loc, '//')) return (parse_url($base, PHP_URL_SCHEME) ?: 'https') . ':' . $loc;
        $p = parse_url($base);
        $root = ($p['scheme'] ?? 'https') . '://' . ($p['host'] ?? '');
        if (isset($p['port'])) $root .= ':' . $p['port'];
        if (str_starts_with($loc, '/')) return $root . $loc;
        $dir = rtrim(dirname($p['path'] ?? '/'), '/');
        return $root . $dir . '/' . $loc;
    }
    private function headerVal(string $raw, string $name): ?string {
        $head = '';
        foreach (array_reverse(preg_split("/\r\n\r\n/", $raw) ?: []) as $b) {
            if (stripos(ltrim($b), 'HTTP/') === 0) { $head = $b; break; }
        }
        foreach (explode("\r\n", $head) as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2 && strtolower(trim($parts[0])) === strtolower($name)) return trim($parts[1]);
        }
        return null;
    }
    private function timing(string $url): array {
        $ch = $this->newHandle($url, 15);
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_exec($ch);
        $i = curl_getinfo($ch);
        $vmap = [0=>'none', 1=>'1.0', 2=>'1.1', 3=>'2 (TLS)', 4=>'2 (cleartext)', 5=>'3'];
        return [
            'dns_lookup_s' => round($i['namelookup_time'] ?? 0, 3),
            'tcp_connect_s' => round($i['connect_time'] ?? 0, 3),
            'tls_handshake_s' => max(0, round(($i['appconnect_time'] ?? 0) - ($i['connect_time'] ?? 0), 3)),
            'time_to_first_byte_s' => round($i['starttransfer_time'] ?? 0, 3),
            'total_s' => round($i['total_time'] ?? 0, 3),
            'download_bytes' => $i['size_download'] ?? 0,
            'speed_bps' => (int)($i['speed_download'] ?? 0),
            'http_version' => $vmap[$i['http_version'] ?? 0] ?? (string)($i['http_version'] ?? 0),
            'primary_ip' => $i['primary_ip'] ?? null,
            'primary_port' => $i['primary_port'] ?? null,
        ];
    }
    private function methods(string $url): array {
        $out = [];
        // PATCH is now actually probed — scan() checked it in risky_methods_accepted
        // but it was never requested, so that check could never fire.
        foreach (['OPTIONS','HEAD','TRACE','PUT','DELETE','PATCH'] as $m) {
            $ch = $this->newHandle($url);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $m);
            if (in_array($m, ['PUT','DELETE','TRACE','PATCH'], true)) curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Length: 0']);
            $raw = (string)curl_exec($ch);
            $info = curl_getinfo($ch);
            $row = ['code' => $info['http_code'] ?? 0];
            if ($m === 'OPTIONS') {
                $allow = $this->headerVal($raw, 'allow');
                if ($allow) $row['allow'] = $allow;
                $dav = $this->headerVal($raw, 'dav');
                if ($dav) $row['dav'] = $dav;
            }
            $out[$m] = $row;
        }
        return $out;
    }
    private function downgrade(array $chain, string $scheme): bool {
        if ($scheme !== 'https') return false;
        foreach ($chain as $s) { if (stripos($s['url'], 'http://') === 0) return true; }
        return false;
    }
}
