<?php
/** Web-Recon: Subnet calculator (hackertarget API) */
class SubnetCalculator {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $host = preg_replace('#^https?://#', '', $target);
        $host = explode('/', $host)[0];
        $r = $this->client ? $this->client->get('http://api.hackertarget.com/subnetcalc/?q=' . urlencode($host)) : ['body'=>''];
        $lines = array_values(array_filter(array_map('trim', explode("\n", (string)($r['body'] ?? '')))));
        return ['target'=>$host,'result'=>$lines];
    }
}
