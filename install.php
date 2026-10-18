<?php
/** Web-Recon installer: checks PHP/exts, creates dirs, inits DB */
echo "Web-Recon 1.0 — installer (Author: cbotrtx)\n\n";
$ok = true;
if (version_compare(PHP_VERSION,'7.4.0','<')) { echo "✗ PHP 7.4+ required (have ".PHP_VERSION.")\n"; $ok=false; }
else echo "✓ PHP ".PHP_VERSION."\n";
foreach (['curl','json'] as $e) echo (extension_loaded($e)?"✓":"✗ MISSING (required)")." ext: $e\n";
foreach (['sqlite3','sockets','pcntl','mbstring'] as $e) echo (extension_loaded($e)?"✓":"! optional missing")." ext: $e\n";
foreach (['assets','cache','logs','results','database'] as $d) { @mkdir(__DIR__."/$d",0755,true); echo "✓ dir: $d\n"; }
if (!file_exists(__DIR__.'/config/api_keys.php')) { @copy(__DIR__.'/config/settings.php', __DIR__.'/config/api_keys.php'); }
if (!file_exists(__DIR__.'/assets/logo.png')) echo "! assets/logo.png missing — place the green hacker logo there (ASCII fallback will be used).\n";
try {
    require_once __DIR__.'/database/DatabaseManager.php';
    require_once __DIR__.'/colors.php';
    new DatabaseManager();
    echo "✓ database initialized\n";
} catch (Throwable $e) { echo "! db init note: ".$e->getMessage()."\n"; }
echo $ok ? "\nDone. Run: ./w_recon.php\n" : "\nFix missing requirements, then re-run.\n";
