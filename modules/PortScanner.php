<?php
/** Web-Recon: TCP port scanner (async connect sweep + banner grab + HTTP-service intuition) */
class PortScanner {
    private $logger; private $config;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->logger=$logger;$this->config=$config; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        global $WR_TOP_PORTS, $WR_EXTENDED_PORTS;
        $ip = filter_var($target,FILTER_VALIDATE_IP) ? $target : gethostbyname($target);
        if ($depth === '1') $ports = $WR_TOP_PORTS ?? [21,22,23,25,53,80,110,143,443,445,3306,3389,5900,8080];
        elseif ($depth === '2') $ports = array_slice($WR_EXTENDED_PORTS ?? $WR_TOP_PORTS, 0, 100);
        else $ports = $WR_EXTENDED_PORTS ?? $WR_TOP_PORTS;
        if ($depth === '3') $ports = array_values(array_unique(array_merge($ports,[81,444,465,587,636,989,990,1080,1194,1434,1720,2375,2376,3000,4444,5000,5555,5432,6379,7000,8000,8008,8081,8443,8888,9000,9042,9090,9100,9200,10000,11211,27017,27018])));
        $timeout = $depth === '1' ? 1.2 : ($depth === '2' ? 2.0 : 2.5);
        $open = []; $closed = 0;
        foreach (array_chunk($ports, 40) as $chunk) {
            $streams = [];
            foreach ($chunk as $p) {
                $s = @stream_socket_client("tcp://$ip:$p", $en, $es, $timeout, STREAM_CLIENT_CONNECT|STREAM_CLIENT_ASYNC_CONNECT);
                if ($s) $streams[$p] = $s; else $closed++;
            }
            if (!$streams) continue;
            $w = $streams; $r = null; $e = null;
            @stream_select($r, $w, $e, (int)ceil($timeout), 200000);
            foreach ($streams as $p=>$s) {
                if (in_array($s, $w, true)) {
                    $banner = $this->grabBanner($s, $p, $timeout);
                    $svc = $this->guessService($p);
                    if ($svc === 'unknown' && stripos($banner, 'HTTP/') !== false) $svc = 'http (detected)';
                    if ($svc === 'unknown' && stripos($banner, 'SSH-') !== false) $svc = 'ssh (detected)';
                    $open[$p] = ['state'=>'open','service'=>$svc,'banner'=>(function_exists('mb_substr')?mb_substr($banner,0,200):substr($banner,0,200))];
                } else $closed++;
                @fclose($s);
            }
        }
        ksort($open);
        return ['host'=>$target,'ip'=>$ip,'ports_scanned'=>count($ports),'open_count'=>count($open),'open'=>$open,'closed_filtered'=>$closed,
            'os_hint'=> $this->osHint(array_keys($open))];
    }
    private function guessService(int $p): string {
        $m=[21=>'ftp',22=>'ssh',23=>'telnet',25=>'smtp',53=>'dns',80=>'http',81=>'http-alt',110=>'pop3',111=>'rpcbind',135=>'msrpc',139=>'netbios',143=>'imap',443=>'https',444=>'snpp',445=>'smb',465=>'smtps',587=>'submission',593=>'http-rpc',636=>'ldaps',989=>'ftps',990=>'ftps',993=>'imaps',995=>'pop3s',1080=>'socks',1194=>'openvpn',1433=>'mssql',1434=>'mssql-udp',1521=>'oracle',1720=>'h323',1723=>'pptp',2049=>'nfs',2082=>'cpanel',2083=>'cpanel-ssl',2086=>'whm',2087=>'whm-ssl',2095=>'webmail',2096=>'webmail-ssl',2222=>'ssh-alt',2375=>'docker',2376=>'docker-ssl',3000=>'dev/grafana',3306=>'mysql',3389=>'rdp',4369=>'epmd',5000=>'upnp/dev',5001=>'iperf',5060=>'sip',5432=>'postgres',5631=>'pcanywhere',5666=>'nrpe',5672=>'amqp',5900=>'vnc',5984=>'couchdb',6000=>'x11',6379=>'redis',6443=>'k8s-api',7001=>'cassandra',8000=>'http-alt',8001=>'http-alt',8008=>'http-alt',8080=>'http-alt',8081=>'http-alt',8083=>'http-alt',8088=>'http-alt',8090=>'http-alt',8443=>'https-alt',8888=>'http-alt',9000=>'sonar/php-fpm',9001=>'torrent/http',9042=>'cassandra',9090=>'http-alt',9100=>'jetdirect',9200=>'elasticsearch',9300=>'elasticsearch',10000=>'webmin',11211=>'memcached',27017=>'mongodb',27018=>'mongodb'];
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
