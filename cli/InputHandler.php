<?php
/**
 * Web-Recon: User input handling & validation
 */
class InputHandler {
    public static function getInput(string $prompt = ''): string {
        if ($prompt !== '') echo $prompt;
        $line = fgets(STDIN);
        return $line === false ? '' : trim($line);
    }
    public static function getChoice(string $prompt, array $valid, string $default = ''): string {
        while (true) {
            $in = strtolower(trim(self::getInput($prompt)));
            if ($in === '' && $default !== '') return strtolower($default);
            foreach ($valid as $v) { if (strtolower((string)$v) === $in) return $in; }
            echo color("Invalid choice. Valid: [" . implode('/', $valid) . "]. Try again.\n", 'bright_red');
        }
    }
    public static function confirm(string $prompt, bool $defaultYes = true): bool {
        $hint = $defaultYes ? '[Y/n]' : '[y/N]';
        $in = strtolower(trim(self::getInput("$prompt $hint: ")));
        if ($in === '') return $defaultYes;
        return in_array($in, ['y','yes','1']);
    }
    public static function sanitizeTarget(string $input): ?string {
        $t = trim(strtolower($input));
        $t = preg_replace('#^https?://#', '', $t);
        $t = explode('/', $t)[0];
        $t = explode(':', $t)[0];
        $t = trim($t);
        if ($t === '') return null;
        if (filter_var($t, FILTER_VALIDATE_IP)) return $t;
        if (filter_var($t, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return $t;
        // allow single-label hostnames for labs
        if (preg_match('/^[a-z0-9]([a-z0-9\-\.]{0,253}[a-z0-9])?$/', $t)) return $t;
        return null;
    }
}
