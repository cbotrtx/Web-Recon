<?php
/**
 * Web-Recon: CLI progress bar
 */
if (!function_exists('color')) require_once __DIR__ . '/../colors.php';
class ProgressBar {
    private $total; private $current = 0; private $label; private $width;
    public function __construct(int $total, string $label = 'Scanning', int $width = 40) {
        $this->total = max(1, $total); $this->label = $label; $this->width = $width;
    }
    public function advance(int $step = 1): void {
        $this->current = min($this->total, $this->current + $step);
        $this->draw();
    }
    public function set(int $n): void { $this->current = min($this->total, $n); $this->draw(); }
    private function draw(): void {
        $pct = $this->current / $this->total;
        $filled = (int)round($this->width * $pct);
        $bar = str_repeat('█', $filled) . str_repeat('░', $this->width - $filled);
        $msg = sprintf("\r%s [%s] %3d%% (%d/%d)", $this->label, $bar, (int)($pct*100), $this->current, $this->total);
        echo color($msg, 'cyan');
        if ($this->current >= $this->total) echo "\n";
    }
    public function finish(): void { $this->set($this->total); }
}
