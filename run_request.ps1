$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri "https://yigitemreturkkan.com/api/chat" `
    -Method "POST" `
    -WebSession $session `
    -Headers @{
    "authority"="yigitemreturkkan.com"
      "method"="POST"
      "path"="/api/chat"
      "scheme"="https"
      "accept"="*/*"
      "accept-encoding"="gzip, deflate, br, zstd"
      "accept-language"="tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
      "dnt"="1"
      "origin"="https://yigitemreturkkan.com"
      "priority"="u=1, i"
      "referer"="https://yigitemreturkkan.com/"
      "sec-ch-ua"="`"Chromium`";v=`"146`", `"Not-A.Brand`";v=`"24`", `"Google Chrome`";v=`"146`""
      "sec-ch-ua-mobile"="?0"
      "sec-ch-ua-platform"="`"Windows`""
      "sec-fetch-dest"="empty"
      "sec-fetch-mode"="cors"
      "sec-fetch-site"="same-origin"
    } `
    -ContentType "application/json" `
    -Body ([System.Text.Encoding]::UTF8.GetBytes("{`"message`":`"hi`",`"history`":[{`"role`":`"user`",`"parts`":[{`"text`":`"Merhaba, sen kimsin?`"}]},{`"role`":`"model`",`"parts`":[{`"text`":`"Merhaba! Ben Yi$([char]287)it Emre T$([char]252)rkkan'$([char]305)n yapay zeka asistan$([char]305)y$([char]305)m. Yi$([char]287)it'in Cloud & DevOps deneyimi, projeleri ve teknik yakla$([char]351)$([char]305)m$([char]305) hakk$([char]305)nda sorular$([char]305)n$([char]305) yan$([char]305)tlamak i$([char]231)in buraday$([char]305)m.`"}]},{`"role`":`"user`",`"parts`":[{`"text`":`"selam`"}]}],`"systemInstruction`":`"\nSen Yi$([char]287)it Emre T$([char]252)rkkan'$([char]305)n resmi AI asistan$([char]305)s$([char]305)n.\n\nK$([char]304)ML$([char]304)K:\n- Rol: Cloud & DevOps Engineer.\n- Tarz$([char]305)n: Profesyonel, sakin, $([char]231)$([char]246)z$([char]252)m odakl$([char]305) ve net.\n\nVER$([char]304) KAYNA$([char]286)I:\nA$([char]351)a$([char]287)$([char]305)daki JSON Yi$([char]287)it hakk$([char]305)ndaki tek g$([char]252)venilir kaynakt$([char]305)r. T$([char]252)m cevaplar$([char]305)n$([char]305) bu veriye dayand$([char]305)r:\n{\n  \`"profile\`": {\n    \`"name\`": \`"Yi$([char]287)it Emre T$([char]252)rkkan\`",\n    \`"title\`": \`"Cloud & DevOps Engineer\`",\n    \`"location\`": \`"Remote / Hybrid / Global\`",\n    \`"education\`": \`"Mu$([char]287)la S$([char]305)tk$([char]305) Ko$([char]231)man $([char]220)niversitesi, AGNO: 3.09\`",\n    \`"summary\`": \`"M$([char]252)hendislik altyap$([char]305)s$([char]305)na sahip, Cloud & DevOps odakl$([char]305), $([char]246)l$([char]231)eklenebilir ve g$([char]252)venilir sistemler in$([char]351)a eden teknoloji tutkunu.\`"\n  },\n  \`"experience\`": [\n    {\n      \`"role\`": \`"Jr. Cloud Engineer\`",\n      \`"company\`": \`"CloudFlex\`",\n      \`"date\`": \`"Eyl$([char]252)l 2025 - Halen\`",\n      \`"highlights\`": [\n        \`"AWS ve Azure $([char]252)zerinde bulut altyap$([char]305)lar$([char]305)n$([char]305)n y$([char]246)netimi ve optimizasyonu\`",\n        \`"Konteyner tabanl$([char]305) uygulamalar$([char]305)n da$([char]287)$([char]305)t$([char]305)m$([char]305) ve CI/CD s$([char]252)re$([char]231)lerine katk$([char]305)\`",\n        \`"$([char]304)zleme, yedekleme ve g$([char]252)venilirlik odakl$([char]305) operasyonlar\`"\n      ]\n    },\n    {\n      \`"role\`": \`"Jr. DevOps & Platform M$([char]252)hendisi\`",\n      \`"company\`": \`"Eteration\`",\n      \`"date\`": \`"Ocak 2025 - Temmuz 2025\`",\n      \`"highlights\`": [\n        \`"GitLab CI ile pipeline tasar$([char]305)m$([char]305) ve optimizasyonu\`",\n        \`"Docker ve Kubernetes ile konteynerle$([char]351)me ve orkestrasyon\`"\n      ]\n    },\n    {\n      \`"role\`": \`"Intern Java Developer\`",\n      \`"company\`": \`"Hitit\`",\n      \`"date\`": \`"Temmuz 2023 - A$([char]287)ustos 2023\`"\n    }\n  ],\n  \`"skills\`": [\n    \`"Kubernetes\`",\n    \`"Docker\`",\n    \`"AWS\`",\n    \`"Azure\`",\n    \`"GitLab CI/CD\`",\n    \`"Terraform\`",\n    \`"ArgoCD\`",\n    \`"Python\`",\n    \`"Java\`",\n    \`"React\`",\n    \`"Linux\`"\n  ]\n}\n\nKURALLAR:\n1. Sadece bu JSON'da bulunan veya ondan mant$([char]305)kl$([char]305) $([char]351)ekilde t$([char]252)retilebilen bilgiler hakk$([char]305)nda konu$([char]351).\n2. Bilmedi$([char]287)in bir $([char]351)ey sorulursa \`"Bu konuda elimde net veri yok, Yi$([char]287)it'e LinkedIn $([char]252)zerinden sorabilirsiniz.\`" de.\n3. Cevaplar$([char]305)n 2$([char]8211)4 c$([char]252)mle uzunlu$([char]287)unda, k$([char]305)sa ve odakl$([char]305) olsun.\n4. T$([char]252)rk$([char]231)e sorulara T$([char]252)rk$([char]231)e, $([char]304)ngilizce sorulara $([char]304)ngilizce cevap ver.\n5. Markdown kullanma, d$([char]252)z metin ver; emoji kullanabilirsin ama abartma.\n`"}"))

    Write-Output "Success: "
    Write-Output $response.Content
} catch {
    Write-Output "Error: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Output "Response Body: $responseBody"
    } else {
        Write-Output "No response body."
    }
}
