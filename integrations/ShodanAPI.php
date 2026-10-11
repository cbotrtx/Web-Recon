<?php
/** Web-Recon integration: Shodan (requires SHODAN_API_KEY) */
class ShodanAPI {
    private $client; private $key;
    public function __construct($client=null,$key=null){ $this->client=$client; $this->key=$key?:getenv('SHODAN_API_KEY'); }
    public function host(string $ip): array {
        if(!$this->key) return ['error'=>'SHODAN_API_KEY not set'];
        $r=$this->client?$this->client->get("https://api.shodan.io/shodan/host/".urlencode($ip)."?key=".urlencode($this->key)):['body'=>''];
        return json_decode($r['body']??'',true)?:['error'=>'bad response'];
    }
    public function dnsResolve(string $host): array {
        if(!$this->key) return ['error'=>'SHODAN_API_KEY not set'];
        $r=$this->client?$this->client->get("https://api.shodan.io/dns/resolve?hostnames=".urlencode($host)."&key=".urlencode($this->key)):['body'=>''];
        return json_decode($r['body']??'',true)?:[];
    }
}
