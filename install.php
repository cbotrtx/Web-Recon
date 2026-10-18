#!/usr/bin/env php
<?php
/** Web-Recon installer: checks PHP/exts, creates dirs, inits DB */
echo "Web-Recon 1.0 — installer (Author: cbotrtx)\n\n";
$ok = true;
if (version_compare(PHP_VERSION,'8.0.0','<')) { echo "✗ PHP 8.0+ required (have ".PHP_VERSION.")\n"; $ok=false; }
else echo "✓ PHP ".PHP_VERSION."\n";
foreach (['curl','json'] as $e) {
    $has = extension_loaded($e);
    if (!$has) $ok = false; // a missing REQUIRED extension must fail the install — previously $ok stayed true and it printed "Done"
    echo ($has?"✓":"✗ MISSING (required)")." ext: $e\n";
}
foreach (['sqlite3','sockets','pcntl','mbstring'] as $e) echo (extension_loaded($e)?"✓":"! optional missing")." ext: $e\n";
foreach (['assets','cache','logs','results','database'] as $d) { @mkdir(__DIR__."/$d",0755,true); echo "✓ dir: $d\n"; }
if (!file_exists(__DIR__.'/config/api_keys.php')) {
    // Write a real api_keys template — previously this copied settings.php over
    // the keys file, producing a file whose shape/keys were wrong for its purpose.
    @file_put_contents(__DIR__.'/config/api_keys.php', "<?php\n/** Web-Recon API keys — DO NOT COMMIT real keys. Prefer env vars. */\nreturn [\n    'shodan_api_key' => getenv('SHODAN_API_KEY') ?: '',\n    'securitytrails_api_key' => getenv('SECURITYTRAILS_API_KEY') ?: '',\n    'hibp_api_key' => getenv('HIBP_API_KEY') ?: '',\n    'whois_api_key' => getenv('WHOIS_API_KEY') ?: '',\n];\n");
    echo "✓ created config/api_keys.php template\n";
}
if (!file_exists(__DIR__.'/assets/logo.png')) echo "! assets/logo.png missing — place the green hacker logo there (ASCII fallback will be used).\n";
try {
    require_once __DIR__.'/database/DatabaseManager.php';
    require_once __DIR__.'/colors.php';
    new DatabaseManager();
    echo "✓ database initialized\n";
} catch (Throwable $e) { echo "! db init note: ".$e->getMessage()."\n"; }
echo $ok ? "\nDone. Run: php w_recon.php (or ./w_recon.php)\n" : "\nFix missing requirements, then re-run.\n";
exit($ok ? 0 : 1);
