<?php
/** Web-Recon: WordPress-specific checks (version, users, listing, plugins) */
class CMSScannerWP {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base="$scheme://$target";
        $r=$this->client?$this->client->get($base.'/'):['body'=>'','code'=>0];
        $body=(string)($r['body']??'');
        $isWP = stripos($body,'wp-content')!==false||stripos($body,'wp-includes')!==false||stripos($body,'wordpress')!==false;
        $out=['is_wordpress'=>$isWP];
        if(!$isWP){ $out['note']='no WordPress fingerprints on homepage'; return $out; }
        if(preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([^"\']*)/i',$body,$m)) $out['version']=$m[1];
        $checks=['/wp-login.php'=>'login','/wp-admin/'=>'admin','/wp-json/wp/v2/users'=>'user_enum','/xmlrpc.php'=>'xmlrpc','/readme.html'=>'readme','/license.txt'=>'license'];
        $urls=array_map(fn($p)=>$base.$p,array_keys($checks));
        $res=$this->client?$this->client->multiGet($urls,[],10):[];
        foreach($res as $u=>$d){
            $label=$checks[substr($u,strlen($base))];
            $out['checks'][$label]=['code'=>$d['code']??0,'exposed'=>in_array($d['code']??0,[200,401,403])];
        }
        // user enumeration via REST
        try{
            $uj=$this->client?$this->client->get($base.'/wp-json/wp/v2/users'):['body'=>''];
            $j=json_decode($uj['body']??'',true);
            if(is_array($j)&&isset($j[0]['slug'])) $out['exposed_users']=array_slice(array_map(fn($x)=>$x['slug']??$x['name']??'?',$j),0,10);
        }catch(Throwable $e){}
        $out['hardening_tips']=['block xmlrpc if unused','disable user enumeration','hide version','limit login attempts','keep core/plugins updated'];
        return $out;
    }
}
