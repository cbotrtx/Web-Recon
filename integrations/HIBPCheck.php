<?php
/** Web-Recon integration: Have I Been Pwned (requires key for v3 API) */
class HIBPCheck {
    private $client; private $key;
    public function __construct($client=null,$key=null){ $this->client=$client; $this->key=$key?:getenv('HIBP_API_KEY'); }
    public function accountBreaches(string $account): array {
        if(!$this->key) return ['error'=>'HIBP_API_KEY not set'];
        $ch=curl_init("https://haveibeenpwned.com/api/v3/breachedaccount/".urlencode($account)."?truncateResponse=false");
        curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>15,CURLOPT_HTTPHEADER=>["hibp-api-key: {$this->key}","user-agent: Web-Recon-1.0"],CURLOPT_SSL_VERIFYPEER=>false]);
        $b=curl_exec($ch); $code=curl_getinfo($ch,CURLINFO_HTTP_CODE);
        if($code===404) return ['account'=>$account,'breaches'=>[],'count'=>0];
        $j=json_decode((string)$b,true);
        return ['account'=>$account,'breaches'=>$j??[],'count'=>is_array($j)?count($j):0];
    }
}
