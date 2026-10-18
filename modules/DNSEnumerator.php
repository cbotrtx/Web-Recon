<?php
/** Web-Recon: DNS record mapping (A, AAAA, MX, NS, TXT, SOA, CNAME) */
class DNSEnumerator {
    private $logger;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->logger=$logger; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $target = function_exists('wr_host_only') ? wr_host_only($target) : $target; // DNS names have no :port / brackets
        $out = ['domain'=>$target];
        $out['A'] = gethostbynamel($target) ?: [];
        $out['A_primary'] = gethostbyname($target);
        foreach (['MX'=>'DNS_MX','NS'=>'DNS_NS','TXT'=>'DNS_TXT','SOA'=>'DNS_SOA','CNAME'=>'DNS_CNAME','AAAA'=>'DNS_AAAA'] as $label=>$const) {
            $recs = @dns_get_record($target, constant($const));
            $out[$label] = $recs ?: [];
        }
        // DoH fallback via Cloudflare for A records (useful when local resolver limited)
        try {
            $ch = curl_init("https://cloudflare-dns.com/dns-query?name=".urlencode($target)."&type=A");
            curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>8,CURLOPT_HTTPHEADER=>['accept: application/dns-json'],CURLOPT_SSL_VERIFYPEER=>false]);
            $r = curl_exec($ch);
            $j = json_decode((string)$r, true);
            if (!empty($j['Answer'])) $out['DoH_A'] = array_column($j['Answer'],'data');
        } catch (Throwable $e) { $out['DoH_error'] = $e->getMessage(); }
        return $out;
    }
}
