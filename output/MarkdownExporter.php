<?php
/** Web-Recon: Markdown report export */
class MarkdownExporter {
    public static function export(array $results, string $target): string {
        $dir = defined('WR_RESULTS')?WR_RESULTS:(__DIR__.'/../results');
        if(!is_dir($dir))@mkdir($dir,0755,true);
        $f=$dir.'/'.preg_replace('/[^a-z0-9.\-]+/i','_',strtolower($target)).'_'.date('Ymd_His').'.md';
        $m="# Web-Recon Report — $target\n\n";
        $meta=$results['_meta']??[];
        $m.="Generated: ".date('Y-m-d H:i:s')." | Tool: Web-Recon ".(defined('WR_VERSION')?WR_VERSION:'1.0')."\n\n";
        if($meta) $m.="Target `{$meta['url']}` | Type `{$meta['scan_type']}` | Depth `{$meta['depth']}` | Duration `{$meta['duration_s']}s`\n\n";
        foreach($results as $mod=>$data){
            if($mod==='_meta')continue;
            $m.="## ".ucfirst($mod)."\n\n```json\n".substr(json_encode($data,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),0,6000)."\n```\n\n";
        }
        file_put_contents($f,$m);
        return $f;
    }
}
