<?php
/** Web-Recon: TCP port scanner (async connect sweep + verification pass + banner grab + HTTP-service intuition) */
class PortScanner {
    private $logger; private $config;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->logger=$logger;$this->config=$config; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        global $WR_TOP_PORTS, $WR_EXTENDED_PORTS;
        $host = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $ip = filter_var($host,FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        $addr = function_exists('wr_socket_host') ? wr_socket_host($ip) : $ip;
        if ($depth === '1') $ports = $WR_TOP_PORTS ?? [21,22,23,25,53,80,110,143,443,445,3306,3389,5900,8080];
        elseif ($depth === '2') $ports = array_slice($WR_EXTENDED_PORTS ?? $WR_TOP_PORTS, 0, 100);
        else {
            // Deep scan must live up to its preset (~1000 ports): extended list + full well-known range 1-1024.
            $base = $WR_EXTENDED_PORTS ?? $WR_TOP_PORTS ?? [];
            $ports = array_values(array_unique(array_merge($base, range(1, 1024))));
            sort($ports);
        }
        $timeout = $depth === '1' ? 1.2 : ($depth === '2' ? 2.0 : 2.5);
        $open = [];
        // Pass 1: fast async sweep, 40 simultaneous connects per chunk.
        $found = $this->sweep($ports, $addr, $timeout, 40);
        // Pass 2 (verification): a 40-at-once burst can lose SYNs on high-latency
        // or lossy links — one dropped handshake pushes the connect past the
        // chunk deadline and an open port is written off as "filtered". Observed
        // against scanme.nmap.org (~0.7s RTT): three runs reported three
        // different subsets of the truly-open ports ({80}, {22}, {}). So every
        // curated-list port that pass 1 missed is re-probed gently — 10 per
        // chunk, double the deadline. Only list ports get the second chance,
        // which bounds the extra time on hosts that drop everything.
        $priority = array_values(array_unique(array_merge($WR_TOP_PORTS ?? [], $WR_EXTENDED_PORTS ?? [])));
        $retry = array_values(array_diff(array_intersect($ports, $priority), array_keys($found)));
        $recovered = 0;
        if ($retry) {
            foreach ($this->sweep($retry, $addr, $timeout * 2, 10) as $p => $s) {
                $found[$p] = $s; $recovered++;
            }
        }
        foreach ($found as $p => $s) {
            $banner = $this->grabBanner($s, $p, $timeout);
            $svc = $this->guessService($p);
            if ($svc === 'unknown' && stripos($banner, 'HTTP/') !== false) $svc = 'http (detected)';
            if ($svc === 'unknown' && stripos($banner, 'SSH-') !== false) $svc = 'ssh (detected)';
            $open[$p] = ['state'=>'open','service'=>$svc,'banner'=>(function_exists('mb_substr')?mb_substr($banner,0,200):substr($banner,0,200))];
            @fclose($s);
        }
        ksort($open);
        return ['host'=>$target,'ip'=>$ip,'ports_scanned'=>count($ports),'open_count'=>count($open),'open'=>$open,'closed_filtered'=>count($ports) - count($open),
            'recovered_on_retry'=>$recovered,
            'os_hint'=> $this->osHint(array_keys($open))];
    }
    /**
     * One async connect sweep over $ports; returns [port => open stream].
     * A port counts as open only when stream_socket_get_name() confirms the
     * peer: a refused non-blocking connect also becomes "writable", which is
     * how the original code came to report every port as open. Connect errors
     * can also surface via select's except set, so that set is checked too.
     * A failed select (e.g. interrupted by a signal) is retried until the
     * deadline instead of abandoning the whole chunk unresolved.
     */
    private function sweep(array $ports, string $addr, float $timeout, int $chunkSize): array {
        $found = [];
        foreach (array_chunk($ports, $chunkSize) as $chunk) {
            $pending = [];
            foreach ($chunk as $p) {
                $s = @stream_socket_client("tcp://$addr:$p", $en, $es, $timeout, STREAM_CLIENT_CONNECT|STREAM_CLIENT_ASYNC_CONNECT);
                if ($s) $pending[$p] = $s;
            }
            $deadline = microtime(true) + $timeout + 0.2;
            $selectFails = 0;
            while ($pending && microtime(true) < $deadline) {
                $w = array_values($pending); $r = []; $e = $w;
                $remain = max(0.05, $deadline - microtime(true));
                $sec = (int)$remain; $usec = (int)(($remain - $sec) * 1000000);
                $n = @stream_select($r, $w, $e, $sec, $usec);
                if ($n === false) {
                    if (++$selectFails >= 5) break;
                    usleep(20000);
                    continue;
                }
                if ($n === 0) break; // select consumed the rest of the deadline
                foreach (array_merge($w, $e) as $s) {
                    $p = array_search($s, $pending, true);
                    if ($p === false) continue;
                    unset($pending[$p]);
                    if (@stream_socket_get_name($s, true) !== false) $found[$p] = $s;
                    else @fclose($s);
                }
            }
            foreach ($pending as $s) @fclose($s);
        }
        return $found;
    }
    private function guessService(int $p): string {
        $m=[21=>'ftp',22=>'ssh',23=>'telnet',25=>'smtp',53=>'dns',80=>'http',81=>'http-alt',110=>'pop3',111=>'rpcbind',135=>'msrpc',139=>'netbios',143=>'imap',443=>'https',444=>'snpp',445=>'smb',465=>'smtps',587=>'submission',593=>'http-rpc',636=>'ldaps',989=>'ftps',990=>'ftps',993=>'imaps',995=>'pop3s',1080=>'socks',1194=>'openvpn',1433=>'mssql',1434=>'mssql-udp',1521=>'oracle',1720=>'h323',1723=>'pptp',2049=>'nfs',2082=>'cpanel',2083=>'cpanel-ssl',2086=>'whm',2087=>'whm-ssl',2095=>'webmail',2096=>'webmail-ssl',2222=>'ssh-alt',2375=>'docker',2376=>'docker-ssl',3000=>'dev/grafana',3306=>'mysql',3389=>'rdp',4369=>'epmd',5000=>'upnp/dev',5001=>'iperf',5060=>'sip',5432=>'postgres',5631=>'pcanywhere',5666=>'nrpe',5672=>'amqp',5900=>'vnc',5984=>'couchdb',6000=>'x11',6379=>'redis',6443=>'k8s-api',7001=>'cassandra',8000=>'http-alt',8001=>'http-alt',8008=>'http-alt',8080=>'http-alt',8081=>'http-alt',8083=>'http-alt',8088=>'http-alt',8090=>'http-alt',9100=>'jetdirect',9200=>'elasticsearch',9300=>'elasticsearch',10000=>'webmin',11211=>'memcached',27017=>'mongodb',27018=>'mongodb'];
        return $m[$p] ?? 'unknown';
    }
    /** OS hint from open-port combination (RDP/SMB/WinRM=Windows; SSH+NFS=Unix-like). */
    private function osHint(array $openPorts): ?string {
        if (in_array(3389, $openPorts, true)) return 'Windows (RDP open)';
        if (in_array(445, $openPorts, true) && in_array(135, $openPorts, true)) return 'Windows (SMB+RPC open)';
        if (in_array(22, $openPorts, true) && !in_array(445, $openPorts, true)) return 'Unix-like (SSH open, no SMB)';
        if (in_array(22, $openPorts, true)) return 'Unix-like (SSH open)';
        return null;
    }
    private function grabBanner($stream, int $port, float $timeout): string {
        @stream_set_timeout($stream, (int)max(1,$timeout));
        $d = @fread($stream, 512);
        $banner = $d === false ? '' : trim((string)$d);
        // Silent service? Try an HTTP HEAD — catches web servers on odd ports
        if ($banner === '' && $this->maybeHttp($port)) {
            @fwrite($stream, "HEAD / HTTP/1.0\r\nHost: x\r\n\r\n");
            $d2 = @fread($stream, 512);
            if ($d2 !== false && stripos((string)$d2, 'HTTP/') !== false) $banner = trim((string)$d2);
        }
        return $banner;
    }
    private function maybeHttp(int $p): bool {
        return in_array($p, [80,81,443,3000,4000,5000,7000,8000,8001,8008,8080,8081,8083,8088,8090,8443,8888,9000,9001,9042,9090,10000], true);
    }
}
