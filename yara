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
        domain in {$weelsfargo.com $welalsfargo.com $welelsfargo.com} and
        all of them
}
