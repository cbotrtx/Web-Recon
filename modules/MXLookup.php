<?php
/** Web-Recon: MX record lookup */
class MXLookup {
    public function __construct($client=null,$cache=null,$logger=null,$config=null){}
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $records = @dns_get_record($target, DNS_MX) ?: [];
        $out = [];
        foreach ($records as $r) {
            $host = $r['target'] ?? null;
            $ip = $host ? @gethostbyname($host) : null;
            $out[] = ['priority'=>$r['pri'] ?? null,'host'=>$host,'ip'=>$ip && $ip !== $host ? $ip : null];
        }
        return ['domain'=>$target,'records'=>$out,'count'=>count($out)];
    }
}
