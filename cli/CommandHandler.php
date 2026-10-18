<?php
/**
 * Web-Recon: Non-interactive command handling (--target, --type, --depth, --export)
 *
 * Accepts both --target=example.com and --target example.com.
 * Invalid values are reported in 'errors' instead of being silently ignored —
 * previously a typo like --type=X or --export=xml silently fell back to a
 * full G audit / no export, which is the opposite of what the user asked for.
 */
class CommandHandler {
    public static function parseArgs(array $argv): array {
        $opts = ['target'=>null,'scheme'=>'https','type'=>'G','depth'=>'2','export'=>null,'proxy'=>null,'modules'=>null,'help'=>false,'errors'=>[]];
        $args = array_slice($argv, 1);
        $valueOpts = ['target','scheme','type','depth','export','proxy','modules'];
        for ($i = 0; $i < count($args); $i++) {
            $a = (string)$args[$i];
            if ($a === '--help' || $a === '-h') { $opts['help'] = true; continue; }
            $name = null; $value = null;
            if (preg_match('/^--([a-z]+)=(.*)$/', $a, $m)) { $name = $m[1]; $value = $m[2]; }
            elseif (preg_match('/^--([a-z]+)$/', $a, $m) && in_array($m[1], $valueOpts, true)) {
                $name = $m[1];
                if ($i + 1 >= count($args) || str_starts_with((string)$args[$i + 1], '--')) {
                    $opts['errors'][] = "--$name requires a value (use --$name=value)";
                    continue;
                }
                $value = (string)$args[++$i];
            } else {
                $opts['errors'][] = "Unknown argument: $a";
                continue;
            }
            switch ($name) {
                case 'target':
                    if ($value === '') $opts['errors'][] = '--target requires a value';
                    else $opts['target'] = $value;
                    break;
                case 'scheme':
                    $v = strtolower($value);
                    if (!in_array($v, ['http','https'], true)) $opts['errors'][] = "Invalid --scheme=$value (expected http or https)";
                    else $opts['scheme'] = $v;
                    break;
                case 'type':
                    $v = strtoupper($value);
                    if (!preg_match('/^[A-H]$/', $v)) $opts['errors'][] = "Invalid --type=$value (expected A-H)";
                    else $opts['type'] = $v;
                    break;
                case 'depth':
                    if (!in_array($value, ['1','2','3'], true)) $opts['errors'][] = "Invalid --depth=$value (expected 1, 2 or 3)";
                    else $opts['depth'] = $value;
                    break;
                case 'export':
                    $v = strtolower($value);
                    if (!in_array($v, ['json','csv','md','html'], true)) $opts['errors'][] = "Invalid --export=$value (expected json, csv, html or md)";
                    else $opts['export'] = $v;
                    break;
                case 'proxy':
                    $opts['proxy'] = $value;
                    break;
                case 'modules':
                    $opts['modules'] = $value;
                    break;
                default:
                    $opts['errors'][] = "Unknown argument: --$name";
            }
        }
        return $opts;
    }
    public static function printHelp(): void {
        echo color("\nWeb-Recon CLI usage:\n", 'bright_green');
        echo "  php w_recon.php [--target=example.com] [--scheme=https] [--type=G] [--depth=2] [--export=json] [--proxy=127.0.0.1:8080] [--modules=os,curl,ports,subdomain]\n";
        echo "  Options also accept a space instead of '=': --target example.com\n";
        echo "  Types: A=Basic B=Infra C=Tech D=Security E=API F=Custom (requires --modules) G=Full H=RED HAWK\n  Depth: 1=Quick 2=Standard 3=Deep\n\n";
    }
}
