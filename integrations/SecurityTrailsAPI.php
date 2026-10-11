<?php
/** Web-Recon integration: SecurityTrails (requires SECURITYTRAILS_API_KEY) */
class SecurityTrailsAPI {
    private $client; private $key;
    public function __construct($client=null,$key=null){ $this->client=$client; $this->key=$key?:getenv('SECURITYTRAILS_API_KEY'); }
    public function subdomains(string $domain): array {
        if(!$this->key) return ['error'=>'SECURITYTRAILS_API_KEY not set'];
        $ch=curl_init("https://api.securitytrails.com/v1/domain/".urlencode($domain)."/subdomains");
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>15,CURLOPT_HTTPHEADER=>["apikey: {$this->key}","accept: application/json"],CURLOPT_SSL_VERIFYPEER=>false]);
        $b=curl_exec($ch);
        return json_decode((string)$b,true)?:['error'=>'bad response'];
    }
}
