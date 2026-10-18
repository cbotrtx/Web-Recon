<?php
/**
 * Web-Recon: Interactive menu system + logo display
 */
require_once __DIR__ . '/InputHandler.php';

class Menu {
    private $logger;
    private $logoPng;
    private $logoAscii;
    public function __construct($logger) {
        $this->logger = $logger;
        $this->logoPng = __DIR__ . '/../assets/logo.png';
        $this->logoAscii = __DIR__ . '/../assets/logo_ascii.txt';
    }
    public function displayLogoWithImage(): void {
        if (file_exists($this->logoAscii)) {
            echo color(@file_get_contents($this->logoAscii) . "\n", 'bright_green');
        } else {
            $this->displayASCIILogo();
        }
        if (file_exists($this->logoPng)) {
            echo color("  [logo: assets/logo.png]\n", 'green');
        }
    }
    public function displayASCIILogo(): void {
        echo color("\n", 'bright_green');
        echo color(" +=============================================================+\n", 'green');
        echo color(" |                                                             |\n", 'green');
        echo color(" |        <>----<>   ", 'neon') . color("WEB-RECON", 'bright_green') . color("   <>----<>        |\n", 'neon');
        echo color(" |                                                             |\n", 'green');
        echo color(" |          Advanced Web Reconnaissance Tool                   |\n", 'bright_green');
        echo color(" |                      Version 1.0                            |\n", 'green');
        echo color(" +=============================================================+\n", 'green');
    }
    public function displayAuthorCredit(): void {
        echo color("+-------------------------------------------------------------+\n", 'bright_green');
        echo color("|  ", 'bright_green') . color("WEB-RECON v" . (defined('WR_VERSION')?WR_VERSION:'1.0'), 'bright_green')
            . color("  ~  Author: ", 'green') . color(defined('WR_AUTHOR')?WR_AUTHOR:'cbotrtx', 'bright_yellow')
            . color("  ~  Ethical use only", 'green') . color("  |\n", 'bright_green');
        echo color("+-------------------------------------------------------------+\n\n", 'bright_green');
    }
    public function displayHeader(): void {
        echo color("  " . (defined('WR_TAGLINE')?WR_TAGLINE:'Advanced Web Reconnaissance & Intelligence Tool') . "\n\n", 'cyan');
    }
    public function displayMainMenu(): void {
        echo color("\n+==================== MAIN MENU ====================+\n", 'green');
        echo color("  [1] ", 'bright_green') . "Start New Scan\n";
        echo color("  [2] ", 'bright_green') . "Load Previous Scan Results\n";
        echo color("  [3] ", 'bright_green') . "View Documentation\n";
        echo color("  [4] ", 'bright_green') . "Settings & Configuration\n";
        echo color("  [5] ", 'bright_green') . "Exit\n";
        echo color("+==================================================+\n", 'green');
    }
    public function displayScanTypeMenu(): void {
        echo "\n" . color("+-------------------------------------------------------------+", 'green') . "\n";
        echo color("|                      SELECT SCAN TYPE                       |", 'bright_green') . "\n";
        echo color("+-------------------------------------------------------------+", 'green') . "\n";
        echo color("  [A] Basic Reconnaissance", 'bright_green') . " - Domain info, DNS, WHOIS, curl probe\n";
        echo color("  [B] Full Infrastructure Scan", 'bright_green') . " - Subdomains, IPs, ports, OS detection\n";
        echo color("  [C] Technology Detection", 'bright_green') . " - CMS, frameworks, tech stack\n";
        echo color("  [D] Security Analysis", 'bright_green') . " - SSL, headers, vulnerabilities\n";
        echo color("  [E] API & Endpoint Discovery", 'bright_green') . " - Hidden endpoints, API routes\n";
        echo color("  [F] Custom Scan", 'bright_green') . " - Select specific modules\n";
        echo color("  [G] Full Audit (All Modules)", 'bright_green') . " - Comprehensive scan\n";
        echo color("  [H] RED HAWK Feature Scan", 'bright_green') . " - Includes all RED HAWK-style checks\n";
        echo color("+-------------------------------------------------------------+\n", 'green');
    }
    public function displayDepthMenu(): void {
        echo color("  [1] Quick Scan (2-5 min)\n", 'bright_green');
        echo color("  [2] Standard Scan (5-15 min)\n", 'bright_green');
        echo color("  [3] Deep Scan (15-45 min)\n", 'bright_green');
    }
}
