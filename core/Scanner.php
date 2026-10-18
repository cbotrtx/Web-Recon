<?php
/**
 * Web-Recon: Main scanner orchestrator.
 * Maps scan types (A-G) to module sets, runs them with progress, returns results.
 */
require_once __DIR__ . '/APIClient.php';
require_once __DIR__ . '/Cache.php';
require_once __DIR__ . '/../cli/ProgressBar.php';

class Scanner {
    private $logger;
    private $config;
    private $client;
    private $cache;
    private $moduleDir;

    public static $SCAN_MAP = [
        'A' => ['dns','whois','geo','headers','curl'],
        'B' => ['dns','subdomain','ports','os','geo','whois'],
        'C' => ['tech','cms','js','headers'],
        'D' => ['ssl','headers','waf','vuln','breach'],
        'E' => ['urls','api','js','cloud'],
        'F' => [], // custom — chosen at runtime
        'G' => ['dns','whois','geo','subdomain','ports','tech','cms','ssl','headers','waf','urls','api','js','vuln','breach','cloud','os','curl'],
        'H' => ['title','dns','whois','geo','subdomain','ports','nmap','tech','cms','ssl','headers','waf','urls','robots','api','js','vuln','breach','cloud','os','curl','subnet','reverseip','sqli','bloggers','crawler','mx'],
    ];

    public static $MODULE_FILES = [
        'dns'       => 'DNSEnumerator.php',
        'whois'     => 'WhoisLookup.php',
        'geo'       => 'IPGeolocation.php',
        'subdomain' => 'SubdomainEnumerator.php',
        'ports'     => 'PortScanner.php',
        'tech'      => 'TechnologyDetector.php',
        'cms'       => 'CMSScannerWP.php',
        'ssl'       => 'SSLAnalyzer.php',
        'headers'   => 'HeaderAnalyzer.php',
        'waf'       => 'WAFDetector.php',
        'urls'      => 'URLDiscovery.php',
        'api'       => 'APIDetector.php',
        'js'        => 'JavaScriptAnalyzer.php',
        'vuln'      => 'VulnerabilityChecker.php',
        'breach'    => 'DataBreachCheck.php',
        'cloud'     => 'CloudStorageEnum.php',
        'os'        => 'OSDetector.php',
        'curl'      => 'CurlScanner.php',
        'title'     => 'SiteTitle.php',
        'robots'    => 'RobotsScanner.php',
        'subnet'    => 'SubnetCalculator.php',
        'mx'        => 'MXLookup.php',
        'nmap'      => 'NmapPortScan.php',
        'reverseip' => 'ReverseIPLookup.php',
        'sqli'      => 'SQLiScanner.php',
        'bloggers'  => 'BloggersView.php',
        'crawler'   => 'Crawler.php',
    ];

    public static $MODULE_CLASS = [
        'dns'=>'DNSEnumerator','whois'=>'WhoisLookup','geo'=>'IPGeolocation',
        'subdomain'=>'SubdomainEnumerator','ports'=>'PortScanner','tech'=>'TechnologyDetector',
        'cms'=>'CMSScannerWP','ssl'=>'SSLAnalyzer','headers'=>'HeaderAnalyzer','waf'=>'WAFDetector',
        'urls'=>'URLDiscovery','api'=>'APIDetector','js'=>'JavaScriptAnalyzer',
        'vuln'=>'VulnerabilityChecker','breach'=>'DataBreachCheck','cloud'=>'CloudStorageEnum','os'=>'OSDetector','curl'=>'CurlScanner',
        'title'=>'SiteTitle','robots'=>'RobotsScanner','subnet'=>'SubnetCalculator','mx'=>'MXLookup','nmap'=>'NmapPortScan','reverseip'=>'ReverseIPLookup','sqli'=>'SQLiScanner','bloggers'=>'BloggersView','crawler'=>'Crawler',
    ];

    public function __construct($logger, $config = null) {
        $this->logger = $logger;
        $this->config = $config;
        $this->client = new APIClient($config, $logger);
        $this->cache  = new Cache(null, $config ? (int)$config->get('cache_ttl', 3600) : 3600);
        $this->moduleDir = __DIR__ . '/../modules';
        foreach (self::$MODULE_FILES as $f) {
            $p = $this->moduleDir . '/' . $f;
            if (file_exists($p)) require_once $p;
        }
    }

    public function modulesFor(string $type, array $custom = []): array {
        $type = strtoupper($type);
        if ($type === 'F') return $custom;
        // Unknown types used to fall back to the full G audit — a typo must never widen a scan.
        if (!isset(self::$SCAN_MAP[$type])) throw new InvalidArgumentException("Unknown scan type '$type' (expected A-H)");
        return self::$SCAN_MAP[$type];
    }

    public function executeScan(string $target, string $scheme, string $scanType, string $depth, array $custom = []): array {
        $scanType = strtoupper($scanType);
        $modules = $this->modulesFor($scanType, $custom);
        if (!$modules) throw new InvalidArgumentException("Scan type $scanType selected no modules — for type F pass at least one module via --modules");
        $started = date('Y-m-d H:i:s');
        $this->logger->section("Running " . count($modules) . " modules against $scheme://$target (depth $depth)");
        $bar = new ProgressBar(count($modules), 'Progress');
        $results = [
            '_meta' => ['target'=>$target,'scheme'=>$scheme,'url'=>"$scheme://$target",'scan_type'=>$scanType,'depth'=>$depth,'started'=>$started,'tool'=>'Web-Recon '.(defined('WR_VERSION')?WR_VERSION:'1.0')],
        ];
        foreach ($modules as $key) {
            $class = self::$MODULE_CLASS[$key] ?? null;
            $this->logger->info("▸ Module: $key" . ($class ? " ($class)" : ''));
            try {
                if ($class && class_exists($class)) {
                    $mod = new $class($this->client, $this->cache, $this->logger, $this->config);
                    $out = method_exists($mod,'scan') ? $mod->scan($target, $scheme, $depth) : ['error'=>'no scan()'];
                    $results[$key] = $out;
                } else {
                    $results[$key] = ['error' => "module $key not loaded"];
                }
            } catch (Throwable $e) {
                $results[$key] = ['error' => $e->getMessage()];
                $this->logger->warning("Module $key failed: " . $e->getMessage());
            }
            $bar->advance();
        }
        $results['_meta']['finished'] = date('Y-m-d H:i:s');
        $results['_meta']['duration_s'] = strtotime($results['_meta']['finished']) - strtotime($started);
        // Dead-scheme guard: if every web module that ran got HTTP code 0, the
        // target almost certainly does not speak the chosen scheme (e.g. an
        // HTTPS scan of an HTTP-only host). Warn loudly instead of presenting
        // the empty results as findings. Modules expose their code under
        // different keys (http_code / probe_code / baseline_404_code).
        if ($scheme === 'https') {
            $ran = 0; $dead = 0;
            foreach (['tech','headers','waf','urls','api','js'] as $m) {
                if (!isset($results[$m]) || !is_array($results[$m])) continue;
                $code = $results[$m]['http_code'] ?? $results[$m]['probe_code'] ?? $results[$m]['baseline_404_code'] ?? null;
                if ($code === null) continue;
                $ran++;
                if ((int)$code === 0) $dead++;
            }
            if ($ran > 0 && $dead === $ran) {
                $warn = "All $ran web modules returned HTTP code 0 — $target looks HTTP-only; rerun with --scheme=http for real results.";
                $results['_warnings'][] = $warn;
                $this->logger->warning("⚠  $warn");
            }
        }
        return $results;
    }
}
