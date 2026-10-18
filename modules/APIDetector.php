<?php
/** Web-Recon: API endpoint detection (swagger/openapi/graphql/wayback + JS hints) */
class APIDetector {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $base="$scheme://$target";
        $cands=['/api','/api/v1','/api/v2','/api/v3','/graphql','/graphiql','/swagger','/swagger.json','/swagger.yaml','/openapi.json','/api-docs','/api/docs','/rest','/v1','/v2','/.well-known/openid-configuration','/actuator','/api/users','/api/status','/api/health','/wp-json/','/wp-json/wp/v2'];
        $urls=array_map(fn($p)=>$base.$p,$cands);
        $res=$this->client?$this->client->multiGet($urls,[],15):[];
        $found=[];
        foreach($res as $u=>$r){
            $code=$r['code']??0; $b=substr((string)($r['body']??''),0,3000);
            // Fixed false positives: the old condition OR'd in "any 200/401/403",
            // which made $isApi meaningless and flagged plain HTML pages as APIs;
            // and the 'rest' substring matched ordinary words like "interest".
            $isApi = in_array($code,[200,201,401,403]) && (stripos($b,'swagger')!==false||stripos($b,'openapi')!==false||stripos($b,'graphql')!==false||stripos($b,'"paths"')!==false||str_starts_with(trim($b),'{')||str_starts_with(trim($b),'['));
            if($isApi) {
                $type='unknown';
                if(stripos($b,'swagger')!==false||stripos($b,'openapi')!==false)$type='swagger/openapi';
                elseif(stripos($b,'graphql')!==false)$type='graphql';
                elseif(stripos($b,'wp-json')!==false)$type='wp-rest';
                $found[]=['url'=>$u,'code'=>$code,'type'=>$type];
            }
        }
        // Wayback hints for /api paths
        $wb=[];
        try{
            $r=$this->client?$this->client->get('https://web.archive.org/cdx/search/cdx?url='.urlencode($target).'/api*&output=json&limit=30&collapse=urlkey'):['body'=>''];
            $j=json_decode($r['body']??'',true);
            if(is_array($j)) foreach(array_slice($j,1,20) as $row) $wb[]=is_array($row)?($row[2]??$row[0]??''):(string)$row;
        }catch(Throwable $e){}
        return ['base'=>$base,'checked'=>count($urls),'apis'=>$found,'count'=>count($found),'wayback_api_hints'=>array_values(array_unique(array_filter($wb)))];
    }
}
