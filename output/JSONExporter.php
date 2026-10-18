<?php
/** Web-Recon: JSON export */
class JSONExporter {
    public static function export(array $results, string $target): string {
        $dir = defined('WR_RESULTS')?WR_RESULTS:(__DIR__.'/../results');
        if(!is_dir($dir))@mkdir($dir,0755,true);
        $f=$dir.'/'.preg_replace('/[^a-z0-9.\-]+/i','_',strtolower($target)).'_'.date('Ymd_His').'.json';
        // Second-resolution timestamps collide on fast repeat scans of the same target — keep every report.
        $baseFile=$f; $n=2; while(file_exists($f)){ $f=preg_replace('/\.[a-z]+$/','',$baseFile).'_'.$n.'.'.pathinfo($baseFile,PATHINFO_EXTENSION); $n++; }
        file_put_contents($f,json_encode($results,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        return $f;
    }
}
