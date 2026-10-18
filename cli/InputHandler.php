<?php
/**
 * Web-Recon: User input handling & validation
 */
class InputHandler {
    private static $eof = false;

    /** True once STDIN reached EOF (Ctrl-D / closed pipe) — callers must stop prompting instead of looping forever. */
    public static function isEof(): bool { return self::$eof; }

    public static function getInput(string $prompt = ''): string {
        if ($prompt !== '') echo $prompt;
        $line = fgets(STDIN);
        if ($line === false) { self::$eof = true; return ''; }
        return trim($line);
    }
    public static function getChoice(string $prompt, array $valid, string $default = ''): string {
        while (true) {
            $in = strtolower(trim(self::getInput($prompt)));
            if (self::$eof) {
                // No more input will ever arrive: fall back instead of spinning forever.
                if ($default !== '') return self::canonical($valid, $default);
                return isset($valid[0]) ? (string)$valid[0] : '';
            }
            if ($in === '' && $default !== '') return self::canonical($valid, $default);
            foreach ($valid as $v) { if (strtolower((string)$v) === $in) return (string)$v; }
            echo color("Invalid choice. Valid: [" . implode('/', $valid) . "]. Try again.\n", 'bright_red');
        }
    }
    /** Return the caller's own spelling of a valid choice (preserves case, e.g. scan types A-G). */
    private static function canonical(array $valid, string $want): string {
        foreach ($valid as $v) { if (strtolower((string)$v) === strtolower($want)) return (string)$v; }
        return $want;
    }
    public static function confirm(string $prompt, bool $defaultYes = true): bool {
        $hint = $defaultYes ? '[Y/n]' : '[y/N]';
        $in = strtolower(trim(self::getInput("$prompt $hint: ")));
        if ($in === '') return $defaultYes;
        return in_array($in, ['y','yes','1']);
    }
    /**
     * Normalize a user-supplied target.
     * - Strips scheme and path, lowercases hostnames.
     * - Preserves an explicit :port (example.com:8080) — it used to be silently dropped,
     *   so every module scanned the default port instead of the requested one.
     * - Preserves IPv6 literals: bare 2001:db8::1 used to be truncated to "2001";
     *   IPv6 is returned bracketed ([2001:db8::1]) so it stays valid inside URLs.
     *   Use wr_host_only() / wr_target_port() (config.php) for DNS/socket lookups.
     */
    public static function sanitizeTarget(string $input): ?string {
        $t = trim($input);
        $t = preg_replace('#^[a-z][a-z0-9+.-]*://#i', '', $t);
        $t = explode('/', $t)[0];
        $t = trim($t);
        if ($t === '') return null;
        // Bracketed IPv6, optional :port — [2001:db8::1]:8080
        if (str_starts_with($t, '[')) {
            if (!preg_match('/^\[([0-9a-fA-F:]+)\](?::(\d{1,5}))?$/', $t, $m)) return null;
            if (!filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return null;
            $port = isset($m[2]) && $m[2] !== '' ? (int)$m[2] : null;
            if ($port !== null && ($port < 1 || $port > 65535)) return null;
            return '[' . strtolower($m[1]) . ']' . ($port !== null ? ':' . $port : '');
        }
        // Bare IPv6 literal (no port possible without brackets)
        if (filter_var($t, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return '[' . strtolower($t) . ']';
        $t = strtolower($t);
        // Host / IPv4 with optional :port
        $host = $t; $port = null;
        if (substr_count($t, ':') === 1) {
            [$host, $p] = explode(':', $t, 2);
            if ($p === '' || !ctype_digit($p)) return null;
            $port = (int)$p;
            if ($port < 1 || $port > 65535) return null;
        } elseif (str_contains($t, ':')) {
            return null; // unbracketed IPv6 with a port, or garbage
        }
        if ($host === '') return null;
        if (filter_var($host, FILTER_VALIDATE_IP)) return $host . ($port !== null ? ':' . $port : '');
        if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return $host . ($port !== null ? ':' . $port : '');
        // allow single-label hostnames for labs
        if (preg_match('/^[a-z0-9]([a-z0-9\-\.]{0,253}[a-z0-9])?$/', $host)) return $host . ($port !== null ? ':' . $port : '');
        return null;
    }
}
