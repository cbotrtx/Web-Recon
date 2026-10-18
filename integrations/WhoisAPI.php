<?php
/** Web-Recon integration: RDAP fallback wrapper (no key) */
class WhoisAPI {
    private $client;
    public function __construct($client=null){ $this->client=$client; }
    public function domain(string $domain): array {
        $r=$this->client?$this->client->get("https://rdap.verisign.com/com/v1/domain/".urlencode($domain)):['body'=>'','code'=>0];
        if(($r['code']??0)===200) return json_decode($r['body'],true)?:[];
        $r2=$this->client?$this->client->get("https://rdap.org/domain/".urlencode($domain)):['body'=>''];
        return json_decode($r2['body']??'',true)?:['error'=>'rdap unavailable'];
    }
}
