<?php
/** Web-Recon: Nmap port scan */
class NmapPortScan {
    public function __construct($client=null,$cache=null,$logger=null,$config=null){}
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $host = preg_replace('#^https?://#', '', $target);
        $host = explode('/', $host)[0];
        $args = $depth === '3' ? '-sV -Pn' : '-F -Pn';
        $cmd = 'timeout 180 nmap ' . $args . ' ' . escapeshellarg($host) . ' 2>&1';
        $raw = trim((string)@shell_exec($cmd));
        return ['target'=>$host,'command'=>$cmd,'raw'=>$raw];
    }
}
