<?php
/**
 * Web-Recon: Logger with colored CLI output + file logging
 */
class Logger {
    private $logFile;
    private $verbose;
    public function __construct(bool $verbose = true, ?string $logFile = null) {
        $this->verbose = $verbose;
        $dir = defined('WR_LOGS') ? WR_LOGS : (__DIR__ . '/../logs');
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        $this->logFile = $logFile ?: $dir . '/wrecon_' . date('Y-m-d') . '.log';
    }
    private function write(string $level, string $msg, string $colorName): void {
        $line = sprintf("[%s] [%s] %s", date('Y-m-d H:i:s'), $level, wr_strip_colors($msg));
        @file_put_contents($this->logFile, $line . PHP_EOL, FILE_APPEND);
        if ($this->verbose) echo color($msg . PHP_EOL, $colorName);
    }
    public function info(string $msg): void    { $this->write('INFO', $msg, 'cyan'); }
    public function success(string $msg): void { $this->write('OK', "✓ $msg", 'bright_green'); }
    public function warning(string $msg): void { $this->write('WARN', "! $msg", 'yellow'); }
    public function error(string $msg): void   { $this->write('ERROR', "✗ $msg", 'bright_red'); }
    public function section(string $title): void {
        if ($this->verbose) {
            echo color("\n── $title ─────────────────────────────────────\n", 'green');
        }
    }
    public function raw(string $msg, string $c = 'white'): void { if ($this->verbose) echo color($msg, $c); }
    public function getLogFile(): string { return $this->logFile; }
}
