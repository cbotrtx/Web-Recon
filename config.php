<?php
/**
 * Web-Recon: Global configuration & constants
 * Author: cbotrtx | Version: 1.0
 */

define('WR_VERSION', '1.0');
define('WR_AUTHOR', 'cbotrtx');
define('WR_NAME', 'WEB-RECON');
define('WR_TAGLINE', 'Advanced Web Reconnaissance & Intelligence Tool');
define('WR_BASE', __DIR__);
define('WR_ASSETS', WR_BASE . '/assets');
define('WR_RESULTS', WR_BASE . '/results');
define('WR_LOGS', WR_BASE . '/logs');
define('WR_CACHE_DIR', WR_BASE . '/cache');
define('WR_CONFIG_DIR', WR_BASE . '/config');
define('WR_DATA_DIR', WR_BASE . '/data');

define('WR_DEFAULT_TIMEOUT', 15);
define('WR_DEFAULT_UA', 'Mozilla/5.0 (X11; Linux x86_64) Web-Recon/1.0 (Security Research; +https://github.com/cbotrtx)');
define('WR_MIN_PHP', '7.4.0');

// Scan depth presets: max ports, wordlist limits, timeouts
$WR_DEPTH_PRESETS = [
    '1' => ['label' => 'Quick',    'ports' => 20,  'words' => 50,  'timeout' => 5,  'threads' => 20],
    '2' => ['label' => 'Standard', 'ports' => 100, 'words' => 300, 'timeout' => 10, 'threads' => 30],
    '3' => ['label' => 'Deep',     'ports' => 1000,'words' => 2000,'timeout' => 15, 'threads' => 50],
];

// Default top ports (quick)
$WR_TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080];

// Extended list for standard/deep (top 100 subset for speed)
$WR_EXTENDED_PORTS = [21,22,23,25,53,80,81,110,111,135,139,143,179,199,443,445,514,515,548,587,593,636,771,789,873,990,993,995,1025,1080,1433,1521,1723,2049,2082,2083,2086,2087,2095,2096,2222,2375,2376,27017,3000,3306,3389,4369,5000,5001,5060,5432,5631,5666,5672,5900,5984,6000,6379,6443,6666,6667,7001,8000,8001,8008,8042,8080,8081,8083,8088,8090,8443,8888,9000,9001,9042,9100,9200,9300,10000,11211,27017,27018,50070,61616];

foreach ([WR_RESULTS, WR_LOGS, WR_CACHE_DIR] as $d) {
    if (!is_dir($d)) @mkdir($d, 0755, true);
}
