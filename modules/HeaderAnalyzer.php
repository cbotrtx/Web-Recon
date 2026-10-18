<?php
/** Web-Recon: HTTP header analysis + security-header grading */
class HeaderAnalyzer {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $url = "$scheme://$target/";
        $r = $this->client ? $this->client->get($url, [], true) : ['headers'=>[],'info'=>[],'code'=>0];
        $h = array_change_key_case($r['headers']??[], CASE_LOWER);
        $need = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-resource-policy'];
        $present = []; $missing = [];
        foreach ($need as $n) { if (isset($h[$n])) $present[$n]=$h[$n]; else $missing[]=$n; }
        // May be a string or (with several Set-Cookie headers) an array — APIClient collects duplicates now.
        $cookies = $h['set-cookie'] ?? null;
        $score = (int)round(count($present)/count($need)*100);
        return [
            'url'=>$url,'http_code'=>$r['code']??0,'server'=>$h['server']??'unknown',
            'powered_by'=>$h['x-powered-by']??null,'all_headers'=>$r['headers']??[],
            'security_headers_present'=>$present,'security_headers_missing'=>$missing,
            'cookies'=>$cookies,'security_score'=>$score,
            'grade'=> $score>=85?'A':($score>=70?'B':($score>=50?'C':($score>=30?'D':'F'))),
            'final_url'=>$r['info']['url']??$url,
        ];
    }
}
