<?php
/** Web-Recon integration: crt.sh Certificate Transparency */
class CRTshAPI {
    private $client;
    public function __construct($client=null){ $this->client=$client; }
    public function lookup(string $domain): array {
        $r=$this->client?$this->client->get("https://crt.sh/?q=".urlencode('%'.$domain)."&output=json"):['body'=>''];
        $j=json_decode($r['body']??'',true);
        $out=[];
        if(is_array($j)) foreach($j as $row) foreach(explode("\n",$row['name_value']??'') as $n){ $n=strtolower(trim($n," \t*.")); if($n!=='')$out[$n]=$row['issuer_name']??'ct'; }
        return ['domain'=>$domain,'results'=>$out,'count'=>count($out)];
    }
}
