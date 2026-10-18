<?php
/** Web-Recon: SSL/TLS certificate analysis */
class SSLAnalyzer {
    public function __construct($client=null,$cache=null,$logger=null,$config=null){}
    public function scan(string $target, string $scheme='https', string $depth='2'): array {
        if ($scheme!=='https') return ['note'=>'target uses HTTP; no TLS to analyze','target'=>$target];
        $host = function_exists('wr_host_only') ? wr_host_only($target) : $target;
        $port = function_exists('wr_target_port') ? (wr_target_port($target) ?? 443) : 443; // was hardcoded 443 even for host:8443 targets
        $addr = function_exists('wr_socket_host') ? wr_socket_host($host) : $host;
        $ctx = stream_context_create(['ssl'=>['capture_peer_cert'=>true,'verify_peer'=>false,'verify_peer_name'=>false,'SNI_enabled'=>true,'peer_name'=>$host]]);
        $out = ['host'=>$host,'port'=>$port];
        $s = @stream_socket_client("ssl://$addr:$port", $en, $es, 10, STREAM_CLIENT_CONNECT, $ctx);
        if (!$s) return array_merge($out,['reachable'=>false,'error'=>trim("$es ($en)") === '(0)' || trim("$es ($en)") === '' ? "TLS connection to $host:$port failed (no error detail from stream layer)" : "$es ($en)"]);
        $params = stream_context_get_params($ctx);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $out['reachable']=true;
        if ($cert) {
            $info = openssl_x509_parse($cert);
            $out['subject']=$info['subject']??[];
            $out['issuer']=$info['issuer']??[];
            $out['valid_from']=isset($info['validFrom_time_t'])?date('Y-m-d H:i:s',$info['validFrom_time_t']):null;
            $out['valid_to']=isset($info['validTo_time_t'])?date('Y-m-d H:i:s',$info['validTo_time_t']):null;
            $out['days_left']=isset($info['validTo_time_t'])?(int)floor(($info['validTo_time_t']-time())/86400):null;
            $out['expired']=($info['validTo_time_t']??PHP_INT_MAX)<time();
            $out['expiring_soon']=($out['days_left']!==null&&$out['days_left']<30);
            $out['san']=isset($info['extensions']['subjectAltName'])?explode(', ',$info['extensions']['subjectAltName']):[];
            $out['signature']=$info['signatureTypeSN']??null;
        }
        // Protocol support probe (best-effort)
        $out['protocols']= $depth==='1' ? ['note'=>'skipped (quick scan)'] : $this->probeProtocols($host, $port);
        @fclose($s);
        return $out;
    }
    private function probeProtocols(string $host, int $port = 443): array {
        $res=[];
        $addr = function_exists('wr_socket_host') ? wr_socket_host($host) : $host;
        foreach ([STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT=> 'TLSv1.2', STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT=>'TLSv1.3'] as $m=>$label) {
            $ctx=stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false,'crypto_method'=>$m,'SNI_enabled'=>true,'peer_name'=>$host]]);
            $s=@stream_socket_client("ssl://$addr:$port",$en,$es,5,STREAM_CLIENT_CONNECT,$ctx);
            $res[$label]= $s!==false; if($s)@fclose($s);
        }
        return $res;
    }
}
