<?php
/** Web-Recon: HTML report generation (self-contained, template-based) */
class HTMLExporter {
    public static function export(array $results, string $target): string {
        $dir = defined('WR_RESULTS')?WR_RESULTS:(__DIR__.'/../results');
        if(!is_dir($dir))@mkdir($dir,0755,true);
        $f=$dir.'/'.preg_replace('/[^a-z0-9.\-]+/i','_',strtolower($target)).'_'.date('Ymd_His').'.html';
        // Second-resolution timestamps collide on fast repeat scans of the same target — keep every report.
        $baseFile=$f; $n=2; while(file_exists($f)){ $f=preg_replace('/\.[a-z]+$/','',$baseFile).'_'.$n.'.'.pathinfo($baseFile,PATHINFO_EXTENSION); $n++; }
        $tpl=__DIR__.'/../templates/report.html';
        $meta=$results['_meta']??[];
        $sections='';
        foreach($results as $mod=>$data){
            if($mod==='_meta')continue;
            $sections.="<section class='card'><h2>".htmlspecialchars(ucfirst($mod))."</h2><pre>".htmlspecialchars(substr(json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),0,8000))."</pre></section>\n";
        }
        if(file_exists($tpl)){
            $html=file_get_contents($tpl);
            $html=str_replace(['{{TARGET}}','{{DATE}}','{{META}}','{{SECTIONS}}'],
                [htmlspecialchars($target),date('Y-m-d H:i:s'),htmlspecialchars(json_encode($meta,JSON_PRETTY_PRINT)),$sections],$html);
        } else {
            $html="<!doctype html><html><head><meta charset='utf-8'><title>Web-Recon $target</title><style>body{background:#0a0f0a;color:#c9f5c9;font-family:monospace;padding:24px}h1{color:#00ff00}.card{border:1px solid #00ff00;margin:12px 0;padding:12px;border-radius:8px}pre{white-space:pre-wrap}</style></head><body><h1>WEB-RECON — ".htmlspecialchars($target)."</h1><p>".date('Y-m-d H:i:s')."</p>$sections</body></html>";
        }
        file_put_contents($f,$html);
        return $f;
    }
}
