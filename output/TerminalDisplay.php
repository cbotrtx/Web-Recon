<?php
/** Web-Recon: Beautiful CLI result rendering */
class TerminalDisplay {
    public static function render(array $results): void {
        echo "\n".color("+=============================================================+",'green')."\n";
        echo color("|                      SCAN RESULTS                           |",'bright_green')."\n";
        echo color("+=============================================================+",'green')."\n";
        $meta=$results['_meta']??[];
        if($meta) echo color(" Target: {$meta['url']}  |  Type: {$meta['scan_type']}  |  Depth: {$meta['depth']}  |  {$meta['duration_s']}s\n",'cyan');
        foreach($results as $cat=>$data){
            if($cat==='_meta')continue;
            echo "\n".color(strtoupper($cat),'bright_green').":\n";
            echo color(str_repeat('-',57)."\n",'green');
            self::printNode($data,1);
        }
        echo "\n".color("+=============================================================+\n",'green');
        echo color("✓ Scan completed successfully!\n",'bright_green');
    }
    private static function printNode($data,int $depth,int $max=12): void {
        $pad=str_repeat('  ',$depth);
        if(!is_array($data)){ echo $pad.substr((string)$data,0,300)."\n"; return; }
        $n=0;
        foreach($data as $k=>$v){
            if(++$n>$max){ echo $pad.color("… (".(count($data)-$max)." more)\n",'cyan'); break; }
            if(is_array($v)){
                $flat=self::short($v);
                echo $pad."• ".color((string)$k.':','bright_yellow')." $flat\n";
            } else {
                $s=substr((string)$v,0,160);
                echo $pad."• ".color((string)$k.':','bright_yellow')." $s\n";
            }
        }
    }
    private static function short(array $v): string {
        if($v===[])return '[]';
        $keys=array_keys($v);
        if($keys===range(0,count($v)-1)) return '['.implode(', ',array_slice(array_map(fn($x)=>is_array($x)?json_encode($x):(string)$x,$v),0,4)).(count($v)>4?' …':'').'] ('.count($v).')';
        $parts=[];foreach(array_slice($v,0,3,true) as $k=>$x)$parts[]="$k=".(is_array($x)?'['.count($x).']':substr((string)$x,0,60));
        return implode('; ',$parts).(count($v)>3?' …':'');
    }
}
