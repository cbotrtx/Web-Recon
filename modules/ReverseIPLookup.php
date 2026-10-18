<?php
/** Web-Recon: Reverse IP lookup + CMS detection */
class ReverseIPLookup {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $host = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        $limit = $depth === '1' ? 5 : ($depth === '2' ? 10 : 20);
        $domains = [];
        $ch = curl_init('http://domains.yougetsignal.com/domains.php');
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>"remoteAddress=$ip&ket=", CURLOPT_TIMEOUT=>20, CURLOPT_SSL_VERIFYPEER=>false]);
        $resp = (string)curl_exec($ch);
        $resp = str_replace(['[',']','"','{','}',' ',':'], ['', '', '', '', '', '', ','], $resp);
        $resp = str_replace(', ,', ',', $resp);
        foreach (explode(',,', $resp) as $d) {
            $d = trim($d, ",\t\n\r\0\x0B");
            if ($d !== '' && $d !== $ip) $domains[] = $d;
        }
        $domains = array_values(array_unique($domains));
        $domains = array_slice($domains, 0, $limit);
        $results = [];
        foreach ($domains as $d) {
            $cms = 'Could Not Detect';
            if ($this->client) {
                $r = $this->client->get("http://$d/", [], false);
                $body = (string)($r['body'] ?? '');
                if (stripos($body, '/wp-content/') !== false || stripos($body, 'content="WordPress') !== false) $cms = 'WordPress';
                elseif (stripos($body, 'Joomla') !== false) $cms = 'Joomla';
                elseif (stripos($body, '/skin/frontend/') !== false) $cms = 'Magento';
                else {
                    $r2 = $this->client->get("http://$d/misc/drupal.js", [], false);
                    if (stripos((string)($r2['body'] ?? ''), 'Drupal') !== false) $cms = 'Drupal';
                }
            }
            $results[] = ['domain'=>$d, 'cms'=>$cms];
        }
        return ['ip'=>$ip, 'total_found'=>count($domains), 'domains'=>$results];
    }
}
