<?php
/**
 * Web-Recon: ANSI color codes & styling
 * Author: cbotrtx | Version: 1.0
 */

$WR_COLORS = [
    'reset'        => "\033[0m",
    'black'        => "\033[0;30m",
    'red'          => "\033[0;31m",
    'green'        => "\033[0;32m",
    'yellow'       => "\033[0;33m",
    'blue'         => "\033[0;34m",
    'magenta'      => "\033[0;35m",
    'cyan'         => "\033[0;36m",
    'white'        => "\033[0;37m",
    'bright_red'   => "\033[1;31m",
    'bright_green' => "\033[1;32m",
    'neon'         => "\033[92m",
    'bright_yellow'=> "\033[1;33m",
    'bright_blue'  => "\033[1;34m",
    'bright_cyan'  => "\033[1;36m",
    'bright_white' => "\033[1;37m",
    'bold'         => "\033[1m",
    'dim'          => "\033[2m",
    'underline'    => "\033[4m",
];

if (!function_exists('color')) {
    /**
     * Wrap text in ANSI color codes. Auto-disables when not a TTY or NO_COLOR set.
     */
    function color(string $text, string $name = 'reset'): string {
        global $WR_COLORS;
        static $enabled = null;
        if ($enabled === null) {
            $enabled = (getenv('NO_COLOR') === false)
                && (function_exists('posix_isatty') ? @posix_isatty(STDOUT) : true);
            // Always allow colors when forced
            if (getenv('FORCE_COLOR')) $enabled = true;
        }
        if (!$enabled) return $text;
        $code = $WR_COLORS[$name] ?? $WR_COLORS['reset'];
        return $code . $text . $WR_COLORS['reset'];
    }
}

if (!function_exists('wr_strip_colors')) {
    function wr_strip_colors(string $text): string {
        return preg_replace('/\033\[[0-9;]*m/', '', $text);
    }
}

if (!function_exists('wr_banner_line')) {
    function wr_banner_line(string $text, int $width = 59): string {
        $plain = wr_strip_colors($text);
        $len = function_exists('mb_strlen') ? mb_strlen($plain) : strlen($plain);
        $pad = max(0, $width - $len);
        return $text . str_repeat(' ', $pad);
    }
}
