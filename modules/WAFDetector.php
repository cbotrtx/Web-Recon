<?php
/** Web-Recon: WAF / firewall detection via headers, cookies, block-probes */
class WAFDetector {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base = "$scheme://$target/";
        $normal = $this->client ? $this->client->get($base, [], true) : ['headers'=>[],'code'=>0,'body'=>''];
        $h = array_change_key_case($normal['headers']??[], CASE_LOWER);
        $blob = strtolower(json_encode($h).' '.substr((string)($normal['body']??''),0,4000));
        $sigs = [
            'Cloudflare'=>['cf-ray','__cfduid','cf-mitigated','cloudflare'],
            'AWS WAF / Shield'=>['x-amzn','awselb','awsalb'],
            'Akamai'=>['akamai','ak_bmsc','x-akamai'],
            'Imperva / Incapsula'=>['incap_ses','visid_incap','incapsula'],
            'Sucuri'=>['sucuri','x-sucuri'],
            'Barracuda'=>['barra','barracuda'],
            'F5 BIG-IP'=>['bigip','f5_','x-waf'],
            'ModSecurity'=>['mod_security','modsecurity','x-mod-sec'],
            'Wordfence'=>['wordfence'],
            'Fortinet FortiWeb'=>['fortiwaf','fortigate'],
            'Palo Alto'=>['paloalto'],
            'StackPath'=>['stackpath'],
            'Fastly'=>['fastly','x-served-by'],
            'Edgecast'=>['ecdf','edgecast'],
            'deny/allow headers'=>['x-firewall','x-waf-status'],
        ];
        $hits=[];
        foreach ($sigs as $waf=>$keys) foreach ($keys as $k) {
            if (str_contains($blob, strtolower($k))) { $hits[]=$waf; break; }
        }
        // Malicious probe: expect 403/block page differences
        $probe = $this->client ? $this->client->get($base.'?x=%3Cscript%3Ealert(1)%3C/script%3E', [], true) : ['code'=>0,'body'=>''];
        $blocked = in_array($probe['code']??0,[403,406,419,429,501,503]) || stripos((string)($probe['body']??''),'blocked')!==false || stripos((string)($probe['body']??''),'forbidden')!==false;
        return ['url'=>$base,'suspected_waf'=>array_values(array_unique($hits)),'waf_likely'=>!empty($hits)||$blocked,'probe_blocked'=>$blocked,'probe_code'=>$probe['code']??0,'server'=>$h['server']??'unknown'];
    }
}
