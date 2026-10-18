<?php
/**
 * Web-Recon: Scan-result persistence.
 * Uses SQLite when available, otherwise JSON-file fallback in results/.db.json
 */
class DatabaseManager {
    private $pdo=null; private $file; private $logger;
    public function __construct($logger=null, ?string $path=null) {
        $this->logger=$logger;
        $dir=__DIR__;
        $dbPath=$path?:($dir.'/wrecon.sqlite');
        if(extension_loaded('sqlite3')||extension_loaded('pdo_sqlite')){
            try{
                $this->pdo=new PDO('sqlite:'.$dbPath);
                $this->pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
                $schema=file_exists($dir.'/schema.sql')?file_get_contents($dir.'/schema.sql'):'';
                if($schema)$this->pdo->exec($schema);
            }catch(Throwable $e){ $this->pdo=null; if($this->logger)$this->logger->warning("SQLite unavailable, using JSON store: ".$e->getMessage()); }
        }
        $this->file=$dir.'/results_fallback.json';
    }
    public function save(array $meta, array $results): int {
        if($this->pdo){
            $st=$this->pdo->prepare("INSERT INTO scans(target,scheme,scan_type,depth,started,finished,duration_s,results_json) VALUES(?,?,?,?,?,?,?,?)");
            $st->execute([$meta['target']??'',$meta['scheme']??'',$meta['scan_type']??'',$meta['depth']??'',$meta['started']??'',$meta['finished']??'',(int)($meta['duration_s']??0),json_encode($results)]);
            return (int)$this->pdo->lastInsertId();
        }
        $all=file_exists($this->file)?(json_decode(file_get_contents($this->file),true)?:[]):[];
        // Next id is max+1, not count+1 — count collides after any deletion/gap.
        $id=1; foreach($all as $r) $id=max($id,(int)($r['id']??0)+1);
        $all[]=array_merge(['id'=>$id],$meta,['results'=>$results]);
        @file_put_contents($this->file,json_encode($all));
        return $id;
    }
    /** @return array<int,array> */
    public function list(int $limit=20): array {
        if($this->pdo){
            $st=$this->pdo->query("SELECT id,target,scheme,scan_type,depth,started,finished,duration_s FROM scans ORDER BY id DESC LIMIT ".(int)$limit);
            return $st->fetchAll(PDO::FETCH_ASSOC)?:[];
        }
        $all=file_exists($this->file)?(json_decode(file_get_contents($this->file),true)?:[]):[];
        $rows=[];
        foreach(array_slice(array_reverse($all),0,$limit) as $r) $rows[]=array_intersect_key($r,array_flip(['id','target','scheme','scan_type','depth','started','finished','duration_s']));
        return $rows;
    }
    public function load(int $id): ?array {
        if($this->pdo){
            $st=$this->pdo->prepare("SELECT * FROM scans WHERE id=?"); $st->execute([$id]);
            $row=$st->fetch(PDO::FETCH_ASSOC);
            if(!$row)return null;
            $row['results']=json_decode($row['results_json']??'{}',true);
            return $row;
        }
        $all=file_exists($this->file)?(json_decode(file_get_contents($this->file),true)?:[]):[];
        foreach($all as $r) if((int)($r['id']??0)===$id) return $r;
        return null;
    }
}
