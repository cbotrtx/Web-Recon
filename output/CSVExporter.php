<?php
/** Web-Recon: CSV export (flattened key findings) */
class CSVExporter {
    public static function export(array $results, string $target): string {
        $dir = defined('WR_RESULTS')?WR_RESULTS:(__DIR__.'/../results');
        if(!is_dir($dir))@mkdir($dir,0755,true);
        $f=$dir.'/'.preg_replace('/[^a-z0-9.\-]+/i','_',strtolower($target)).'_'.date('Ymd_His').'.csv';
        // Second-resolution timestamps collide on fast repeat scans of the same target — keep every report.
        $baseFile=$f; $n=2; while(file_exists($f)){ $f=preg_replace('/\.[a-z]+$/','',$baseFile).'_'.$n.'.'.pathinfo($baseFile,PATHINFO_EXTENSION); $n++; }
        $fp=fopen($f,'w');
        fputcsv($fp,['module','key','value']);
        foreach($results as $mod=>$data){
            if($mod==='_meta')continue;
            self::flatten($fp,(string)$mod,$data);
        }
        fclose($fp);
        return $f;
    }
    private static function flatten($fp,string $mod,$data,string $prefix=''): void {
        if(!is_array($data)){ fputcsv($fp,[$mod,$prefix,is_string($data)?substr($data,0,500):json_encode($data)]); return; }
        foreach($data as $k=>$v){
            $key=$prefix===''?(string)$k:$prefix.'.'.$k;
            if(is_array($v)&&(array_keys($v)!==range(0,count($v)-1)||count($v)>8)){ self::flatten($fp,$mod,$v,$key); }
            elseif(is_array($v)){ fputcsv($fp,[$mod,$key,substr(json_encode($v),0,500)]); }
            else fputcsv($fp,[$mod,$key,substr((string)$v,0,500)]);
        }
    }
}
