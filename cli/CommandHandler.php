<?php
/**
 * Web-Recon: Non-interactive command handling (--target, --type, --depth, --export)
 */
class CommandHandler {
    public static function parseArgs(array $argv): array {
        $opts = ['target'=>null,'scheme'=>'https','type'=>'G','depth'=>'2','export'=>null,'proxy'=>null,'modules'=>null,'help'=>false];
        foreach ($argv as $a) {
            if (preg_match('/^--target=(.+)$/', $a, $m)) $opts['target'] = $m[1];
            elseif (preg_match('/^--scheme=(.+)$/', $a, $m)) $opts['scheme'] = strtolower($m[1]) === 'http' ? 'http' : 'https';
            elseif (preg_match('/^--type=([A-Ha-h])$/', $a, $m)) $opts['type'] = strtoupper($m[1]);
            elseif (preg_match('/^--depth=([123])$/', $a, $m)) $opts['depth'] = $m[1];
            elseif (preg_match('/^--export=(json|csv|md|html)$/', $a, $m)) $opts['export'] = $m[1];
            elseif (preg_match('/^--proxy=(.+)$/', $a, $m)) $opts['proxy'] = $m[1];
            elseif (preg_match('/^--modules=(.+)$/', $a, $m)) $opts['modules'] = $m[1];
            elseif ($a === '--help' || $a === '-h') $opts['help'] = true;
        }
        return $opts;
    }
    public static function printHelp(): void {
        echo color("\nWeb-Recon CLI usage:\n", 'bright_green');
        echo "  ./w_recon.php [--target=example.com] [--scheme=https] [--type=G] [--depth=2] [--export=json] [--proxy=127.0.0.1:8080] [--modules=os,curl,ports,subdomain]\n";
        echo "  Types: A=Basic B=Infra C=Tech D=Security E=API F=Custom G=Full H=RED HAWK\n  Depth: 1=Quick 2=Standard 3=Deep\n\n";
    }
}
