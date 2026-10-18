<?php
/** Web-Recon: Tech-stack fingerprinting from headers + HTML markers */
class TechnologyDetector {
    private $client;
    public function __construct($client=null,$cache=null,$logger=null,$config=null){ $this->client=$client; }
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        $url = "$scheme://$target/";
        $r = $this->client ? $this->client->get($url, [], true) : ['body'=>'','headers'=>[],'code'=>0];
        $body = (string)($r['body']??'');
        $h = array_change_key_case($r['headers']??[], CASE_LOWER);
        $tech = [];
        // Server / powered-by
        if (!empty($h['server'])) $tech['web_server']=$h['server'];
        if (!empty($h['x-powered-by'])) $tech['powered_by']=$h['x-powered-by'];
        if (!empty($h['x-generator'])) $tech['generator']=$h['x-generator'];
        // CMS markers
        $markers = [
            'WordPress'=>['wp-content','wp-includes','wp-json'],
            'Joomla'=>['/media/joomla','com_content','joomla'],
            'Drupal'=>['sites/default/files','drupal.js','Drupal.settings'],
            'Magento'=>['mage/cookies','Magento_','/static/frontend'],
            'Shopify'=>['cdn.shopify.com','Shopify.theme'],
            'Wix'=>['wixstatic.com','wix.com'],
            'Ghost'=>['ghost.io','/ghost/api'],
            'Next.js'=>['/_next/static','__NEXT_DATA__'],
            'Nuxt.js'=>['/_nuxt/','__NUXT__'],
            'React'=>['react-dom','data-reactroot','__REACT'],
            'Angular'=>['ng-version','app-root','angular.js'],
            'Vue.js'=>['data-v-','__VUE__','vue.js'],
            'Laravel'=>['laravel_session','XSRF-TOKEN'],
            'Django'=>['csrftoken','django'],
            'Rails'=>['_rails','csrf-param'],
            'ASP.NET'=>['__VIEWSTATE','asp.net','X-AspNet'],
            'PHP'=>['phpsessid','.php'],
            'Cloudflare'=>['cf-ray','__cfduid','cloudflare'],
            'Akamai'=>['akamai','ak_bmsc'],
            'Fastly'=>['x-served-by: cache-','fastly'],
            'Google Analytics'=>['google-analytics.com','gtag(','ga('],
            'jQuery'=>['jquery','jQuery('],
            'Bootstrap'=>['bootstrap.min.css','bootstrap.min.js'],
            'Tailwind'=>['tailwindcss','tailwind.'],
            'Wordfence'=>['wordfence'],
        ];
        $blob = strtolower($body . ' ' . json_encode($r['headers']??[]));
        foreach ($markers as $name=>$keys) foreach ($keys as $k) {
            if (str_contains($blob, strtolower($k))) { $tech['detected'][]=$name; break; }
        }
        $tech['detected']=array_values(array_unique($tech['detected']??[]));
        // Generator meta tag
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i',$body,$m)) $tech['meta_generator']=$m[1];
        // JS libs
        preg_match_all('/<script[^>]+src=["\']([^"\']+)/i',$body,$sm);
        $tech['script_count']=count($sm[1]??[]);
        if ($depth!=='1') $tech['script_srcs']=array_slice($sm[1]??[],0,30);
        return array_merge(['url'=>$url,'http_code'=>$r['code']??0],$tech);
    }
}
