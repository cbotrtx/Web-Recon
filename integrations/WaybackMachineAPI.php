<?php
/** Web-Recon integration: Internet Archive CDX */
class WaybackMachineAPI {
    private $client;
    public function __construct($client=null){ $this->client=$client; }
    public function urls(string $domain, int $limit=100): array {
        $u="https://web.archive.org/cdx/search/cdx?url=".urlencode($domain).'/*&output=json&limit='.$limit.'&collapse=urlkey';
        $r=$this->client?$this->client->get($u):['body'=>''];
        $j=json_decode($r['body']??'',true);
        if(!is_array($j)) return ['domain'=>$domain,'urls'=>[],'count'=>0];
        $urls=[]; foreach(array_slice($j,1) as $row) $urls[]=is_array($row)?($row[2]??$row[0]):(string)$row;
        return ['domain'=>$domain,'urls'=>array_values(array_unique($urls)),'count'=>count(array_unique($urls))];
    }
    public function snapshot(string $url): ?string {
        $r=$this->client?$this->client->get("https://archive.org/wayback/available?url=".urlencode($url)):['body'=>''];
        $j=json_decode($r['body']??'',true);
        return $j['closest']['url']??null;
    }
}
