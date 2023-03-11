rule detect_phishing_campaign {
    meta:
        description = "Detects a phishing campaign targeting the financial and insurance sector"
        author = "Fevar54"
        date = "2023-03-11"
    strings:
        $domain1 = "wellbsfargo.com"
        $domain2 = "wellusfargo.com"
        $domain3 = "welwlsfargo.com"
    condition:
        domain in {$domain1 $domain2 $domain3} and
        all of them
