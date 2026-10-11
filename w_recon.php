#!/usr/bin/env php
<?php
/**
 * Web-Recon: Advanced Web Reconnaissance CLI Tool
 * Main Entry Point — Author: cbotrtx, Version: 1.0
 * Usage: ./w_recon.php [--target=example.com --scheme=https --type=G --depth=2 --export=json --modules=os,curl]
 */
error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/colors.php';
require_once __DIR__ . '/core/Config.php';
require_once __DIR__ . '/core/Logger.php';
require_once __DIR__ . '/core/Scanner.php';
require_once __DIR__ . '/cli/Menu.php';
require_once __DIR__ . '/cli/InputHandler.php';
require_once __DIR__ . '/cli/CommandHandler.php';
require_once __DIR__ . '/output/JSONExporter.php';
require_once __DIR__ . '/output/CSVExporter.php';
require_once __DIR__ . '/output/HTMLExporter.php';
require_once __DIR__ . '/output/MarkdownExporter.php';
require_once __DIR__ . '/output/TerminalDisplay.php';
require_once __DIR__ . '/database/DatabaseManager.php';

$logger = new Logger();
$config = new WR_Config();
$menu = new Menu($logger);

if (version_compare(PHP_VERSION, WR_MIN_PHP) < 0) {
    $logger->error("PHP " . WR_MIN_PHP . "+ required. Current: " . PHP_VERSION);
    exit(1);
}
foreach (['curl','json'] as $ext) {
    if (!extension_loaded($ext)) { $logger->error("Missing required PHP extension: $ext"); exit(1); }
}
foreach (['sqlite3','sockets','pcntl'] as $ext) {
    if (!extension_loaded($ext)) $logger->warning("Optional extension not loaded: $ext");
}

// Non-interactive mode
$opts = CommandHandler::parseArgs($argv);
if ($opts['help']) { CommandHandler::printHelp(); exit(0); }
if ($opts['target']) {
    $t = InputHandler::sanitizeTarget($opts['target']);
    if (!$t) { $logger->error("Invalid target."); exit(1); }
    if ($opts['proxy']) $config->set('proxy', $opts['proxy']);
    $ctype = $opts['type']; $custom = [];
    if (!empty($opts['modules'])) {
        $valid = array_keys(Scanner::$MODULE_FILES);
        $custom = array_values(array_intersect(array_map('strtolower', array_map('trim', explode(',', $opts['modules']))), $valid));
        if (!$custom) { $logger->error("No valid modules in --modules. Valid: " . implode(',', $valid)); exit(1); }
        $ctype = 'F';
    }
    runScan($t, $opts['scheme'], $ctype, $opts['depth'], $opts['proxy'] ? 'proxy' : null, $opts['export'], $custom);
    exit(0);
}

// Interactive banner
$menu->displayLogoWithImage();
$menu->displayAuthorCredit();
$menu->displayHeader();

while (true) {
    $menu->displayMainMenu();
    $choice = trim(InputHandler::getInput(color("Select option (1-5): ", 'bright_yellow')));
    switch ($choice) {
        case '1': handleNewScan(); break;
        case '2': handleLoadResults(); break;
        case '3': handleDocumentation(); break;
        case '4': handleSettings(); break;
        case '5': $logger->success("Thank you for using Web-Recon. Goodbye!"); exit(0);
        default: $logger->error("Invalid option. Please choose 1-5.");
    }
}

function handleNewScan(): void {
    global $logger, $menu, $config;
    $raw = InputHandler::getInput(color("\nEnter target URL (e.g., example.com): ", 'bright_yellow'));
    $target = InputHandler::sanitizeTarget($raw);
    if (!$target) { $logger->error("Invalid target URL."); return; }

    $logger->info("Select protocol:");
    echo color("  [1] HTTPS (Secure)\n", 'bright_green');
    echo color("  [2] HTTP (Insecure)\n", 'bright_green');
    $p = InputHandler::getChoice(color("Choice [1-2]: ", 'bright_yellow'), ['1','2'], '1');
    $scheme = ($p === '2') ? 'http' : 'https';

    $menu->displayScanTypeMenu();
    $type = strtoupper(InputHandler::getChoice(color("Select scan type (A-G): ", 'bright_yellow'), ['A','B','C','D','E','F','G'], 'G'));

    $custom = [];
    if ($type === 'F') {
        echo color("Available modules: dns, whois, geo, subdomain, ports, os, tech, cms, ssl, headers, waf, curl, urls, api, js, vuln, breach, cloud\n", 'cyan');
        $in = InputHandler::getInput(color("Comma-separated modules (default: dns,headers,tech): ", 'bright_yellow'));
        $custom = array_values(array_filter(array_map('trim', explode(',', $in === '' ? 'dns,headers,tech' : $in))));
        $valid = array_keys(Scanner::$MODULE_FILES);
        $custom = array_values(array_intersect(array_map('strtolower', $custom), $valid));
        if (!$custom) { $logger->error("No valid modules chosen."); return; }
    }

    $logger->info("Select scan depth:");
    $menu->displayDepthMenu();
    $depth = InputHandler::getChoice(color("Choice [1-3]: ", 'bright_yellow'), ['1','2','3'], '2');

    $anon = InputHandler::getChoice(color("Enable proxy/anonymity? [1=Yes, 2=No]: ", 'bright_yellow'), ['1','2'], '2');
    $proxy = null;
    if ($anon === '1') {
        $proxy = InputHandler::getInput(color("Proxy (host:port, empty=cancel): ", 'bright_yellow'));
        if ($proxy !== '') $config->set('proxy', $proxy);
    }

    $logger->success("Starting scan on: $scheme://$target\n");
    runScan($target, $scheme, $type, $depth, null, null, $custom);
}

function runScan(string $target, string $scheme, string $type, string $depth, ?string $proxyNote = null, ?string $autoExport = null, array $custom = []): void {
    global $logger, $config;
    $scanner = new Scanner($logger, $config);
    $results = $scanner->executeScan($target, $scheme, $type, $depth, $custom);
    TerminalDisplay::render($results);

    // Persist: DB + auto JSON snapshot
    try {
        $db = new DatabaseManager($logger);
        $id = $db->save($results['_meta'], $results);
        $logger->success("Saved to database (id=$id).");
    } catch (Throwable $e) { $logger->warning("DB save failed: " . $e->getMessage()); }
    $jsonFile = JSONExporter::export($results, $target);
    $logger->success("Snapshot: $jsonFile");

    if ($autoExport) { handleExportOptions($results, $target, $autoExport); return; }
    if (InputHandler::confirm(color("\nExport report?", 'bright_yellow'), true)) handleExportOptions($results, $target);
}

function handleExportOptions(array $results, string $target, ?string $preset = null): void {
    global $logger;
    $fmt = $preset;
    if (!$fmt) {
        echo color("  [1] JSON   [2] CSV   [3] HTML   [4] Markdown\n", 'bright_green');
        $c = InputHandler::getChoice(color("Format [1-4]: ", 'bright_yellow'), ['1','2','3','4'], '1');
        $fmt = ['1'=>'json','2'=>'csv','3'=>'html','4'=>'md'][$c];
    }
    try {
        $f = match($fmt) {
            'csv' => CSVExporter::export($results, $target),
            'html' => HTMLExporter::export($results, $target),
            'md' => MarkdownExporter::export($results, $target),
            default => JSONExporter::export($results, $target),
        };
        $logger->success("Exported ($fmt): $f");
    } catch (Throwable $e) { $logger->error("Export failed: " . $e->getMessage()); }
}

function handleLoadResults(): void {
    global $logger;
    $db = new DatabaseManager($logger);
    $rows = $db->list(20);
    // Also list raw JSON snapshots
    $files = glob((defined('WR_RESULTS')?WR_RESULTS:__DIR__.'/results').'/*.json') ?: [];
    if (!$rows && !$files) { $logger->warning("No previous results found."); return; }
    if ($rows) {
        echo color("\nSaved scans (database):\n", 'bright_green');
        foreach ($rows as $r) echo color("  [{$r['id']}] ", 'bright_yellow') . "{$r['scheme']}://{$r['target']}  type={$r['scan_type']} depth={$r['depth']}  {$r['started']} ({$r['duration_s']}s)\n";
        $id = InputHandler::getInput(color("Enter scan id to view (empty=cancel): ", 'bright_yellow'));
        if ($id !== '' && ctype_digit($id)) {
            $row = $db->load((int)$id);
            if ($row && isset($row['results'])) { TerminalDisplay::render($row['results']); return; }
            $logger->error("Scan #$id not found.");
        }
    }
    if ($files) {
        echo color("\nJSON snapshots:\n", 'bright_green');
        foreach (array_slice($files, -10) as $i=>$f) echo color("  [$i] ", 'bright_yellow') . basename($f) . "\n";
    }
}

function handleDocumentation(): void {
    echo color("\nWeb-Recon 1.0 — Quick Docs\n", 'bright_green');
    echo color("Author: cbotrtx. For authorized testing only.\n\n", 'cyan');
    echo "  Scan types: A=Basic B=Infra C=Tech D=Security E=API F=Custom G=Full\n";
    echo "  Depth: 1=Quick 2=Standard 3=Deep (controls ports/wordlist/probes)\n";
    echo "  Non-interactive: ./w_recon.php --target=example.com --type=G --depth=2 --export=json --modules=os,curl\n";
    echo "  API keys: set SHODAN_API_KEY / SECURITYTRAILS_API_KEY / HIBP_API_KEY env vars\n";
    echo "  Results: results/ (+ SQLite database/database/wrecon.sqlite)\n";
    echo "  Full guide: README.md\n\n";
}

function handleSettings(): void {
    global $logger, $config;
    echo color("\nCurrent settings:\n", 'bright_green');
    foreach ($config->all() as $k=>$v) {
        if (str_contains($k,'key') && $v) $v = substr((string)$v,0,4).'…';
        echo color("  $k: ", 'bright_yellow') . var_export($v, true) . "\n";
    }
    $t = InputHandler::getInput(color("Request timeout seconds (empty=keep): ", 'bright_yellow'));
    if ($t !== '' && ctype_digit($t)) { $config->set('timeout', (int)$t); $logger->success("Timeout set to $t."); }
    $px = InputHandler::getInput(color("Proxy host:port (empty=none): ", 'bright_yellow'));
    $config->set('proxy', $px === '' ? null : $px);
    $logger->success($px === '' ? "Proxy cleared." : "Proxy set to $px.");
}
