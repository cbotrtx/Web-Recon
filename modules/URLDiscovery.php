<?php
/** Web-Recon: Hidden endpoint / path discovery via wordlist probing */
class URLDiscovery {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $limits=['1'=>40,'2'=>150,'3'=>600]; $limit=$limits[$depth]??150;
        $wl=$this->wordlist();
        $base="$scheme://$target";
        $paths=array_slice($wl,0,$limit);
        $urls=array_map(fn($p)=>$base.'/'.ltrim($p,'/'),$paths);
        $res=$this->client?$this->client->multiGet($urls,[],25):[];
        // Baseline 404 fingerprint (random path) to filter soft-404s
        $rand=$base.'/_wrecon_'.bin2hex(random_bytes(4));
        $b=$this->client?$this->client->get($rand):['code'=>404,'body'=>''];
        $baseLen=strlen((string)($b['body']??''));
        $found=[];
        foreach($res as $u=>$r){
            $code=$r['code']??0; $len=strlen((string)($r['body']??''));
            if(in_array($code,[200,201,202,204,301,302,303,307,308,401,403])){
                if(abs($len-$baseLen)<200 && in_array($code,[200,404])) continue; // soft-404
                $found[]=['url'=>$u,'code'=>$code,'size'=>$len];
            }
        }
        return ['base'=>$base,'probed'=>count($urls),'baseline_404_code'=>$b['code']??0,'interesting'=>array_slice($found,0,100),'count'=>count($found)];
    }
    private function wordlist(): array {
        $f=__DIR__.'/../data/wordlists/endpoints.txt';
        if(file_exists($f)){ $w=array_values(array_filter(array_map('trim',file($f,FILE_IGNORE_NEW_LINES)))); if($w)return $w; }
        return explode(',', 'admin,login,wp-admin,wp-login.php,administrator,dashboard,panel,api,api/v1,api/v2,graphql,graphiql,swagger,swagger.json,openapi.json,.well-known/security.txt,robots.txt,sitemap.xml,.git/HEAD,.env,config.php,phpinfo.php,server-status,actuator,actuator/health,health,metrics,debug,console,test,old,backup,bak,tmp,uploads,images,css,js,assets,static,includes,inc,lib,src,app,web,site,private,secret,hidden,internal,dev,development,staging,qa,prod,beta,demo,portal,user,users,account,accounts,profile,register,signup,signin,logout,password,reset,forgot,auth,oauth,token,session,search,contact,about,help,faq,docs,documentation,blog,news,forum,shop,cart,checkout,payment,order,orders,invoice,report,reports,stats,analytics,status,monitor,server,db,sql,database,backup.zip,site.zip,www.zip,config.json,package.json,composer.json,yarn.lock,Dockerfile,docker-compose.yml,.dockerignore,README.md,CHANGELOG.md,LICENSE,error_log,access_log,debug.log,app.log,.htaccess,.htpasswd,web.config,crossdomain.xml,clientaccesspolicy.xml,security.txt,humans.txt,ads.txt,app-ads.txt,jwks.json,.well-known/openid-configuration,.well-known/change-password,oauth/token,api-docs,v1,v2,v3,rest,json,xml,rss,feed,sitemap,media,files,download,downloads,export,import,upload,api/users,api/admin,admin.php,login.php');
    }
}
