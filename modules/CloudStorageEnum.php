<?php
/** Web-Recon: Cloud storage misconfiguration enumeration (S3/GCS/Azure hints) */
class CloudStorageEnum {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $hostOnly = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $base=explode('.',strtolower($hostOnly))[0];
        $cands=[
            "https://$base.s3.amazonaws.com","https://s3.amazonaws.com/$base",
            "https://$base.storage.googleapis.com","https://storage.googleapis.com/$base",
            "https://$base.blob.core.windows.net","https://$base.s3-website-us-east-1.amazonaws.com",
            "$scheme://$target/.s3cfg","$scheme://$target/s3.json",
        ];
        $res=$this->client?$this->client->multiGet($cands,[],10):[];
        $hits=[];
        foreach($res as $u=>$r){
            $code=$r['code']??0; $b=substr((string)($r['body']??''),0,2000);
            $open = $code===200 && (stripos($b,'ListBucketResult')!==false||stripos($b,'xml')!==false||strlen($b)>200);
            if($open||in_array($code,[200,403])) $hits[]=['url'=>$u,'code'=>$code,'possibly_exposed'=>$open];
        }
        return ['keyword'=>$base,'checked'=>count($cands),'candidates'=>$hits,'count'=>count($hits),'hint'=>'403 = exists but private; 200+XML listing = PUBLIC — verify manually'];
    }
}
