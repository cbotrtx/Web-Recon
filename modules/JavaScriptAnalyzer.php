<?php
/** Web-Recon: JS file discovery + secret/endpoint mining */
class JavaScriptAnalyzer {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $url="$scheme://$target/";
        $r=$this->client?$this->client->get($url):['body'=>''];
        $body=(string)($r['body']??'');
        preg_match_all('/<script[^>]+src=["\']([^"\']+)["\']/i',$body,$m);
        $srcs=array_values(array_unique($m[1]??[]));
        $abs=array_slice(array_map(fn($s)=> $this->abs($s,$scheme,$target), $srcs),0,$depth==='1'?5:20);
        $secrets=[]; $endpoints=[]; $analyzed=0;
        if($this->client && $abs){
            $res=$this->client->multiGet($abs,[],10);
            foreach($res as $u=>$d){
                $js=(string)($d['body']??''); if($js==='')continue; $analyzed++;
                foreach([
                    'aws_key'=>'/AKIA[0-9A-Z]{16}/','google_key'=>'/AIza[0-9A-Za-z\-_]{35}/',
                    'generic_secret'=>'/(api[_-]?key|secret|token)\s*[:=]\s*["\'][^"\']{4,}["\']/i',
                    'private_key'=>'/-----BEGIN [A-Z ]*PRIVATE KEY-----/',
                    'slack'=>'/xox[bap]-[0-9A-Za-z\-]+/','github'=>'/gh[pousr]_[0-9A-Za-z]{36,}/',
                ] as $name=>$pat){ if(preg_match($pat,$js,$mm)) $secrets[]=['file'=>$u,'type'=>$name,'match'=>substr($mm[0],0,80)]; }
                preg_match_all('#["\'](/[a-zA-Z0-9_\-/]{2,}(?:\?[^\s"\']*)?)["\']#',$js,$em);
                foreach(array_slice(array_unique($em[1]??[]),0,40) as $e){ if(!str_starts_with($e,'//')) $endpoints[]=['file'=>$u,'path'=>$e]; }
                if(count($secrets)>25||count($endpoints)>200) break;
            }
        }
        return ['page'=>$url,'script_srcs_total'=>count($srcs),'scripts_analyzed'=>$analyzed,'potential_secrets'=>array_slice($secrets,0,30),'js_endpoints'=>array_slice($endpoints,0,100),'secret_count'=>count($secrets),'endpoint_count'=>count($endpoints)];
    }
    private function abs(string $s,string $scheme,string $host): string {
        if(str_starts_with($s,'http'))return $s;
        if(str_starts_with($s,'//'))return $scheme.':'.$s;
        if(str_starts_with($s,'/'))return "$scheme://$host$s";
        return "$scheme://$host/$s";
    }
}
