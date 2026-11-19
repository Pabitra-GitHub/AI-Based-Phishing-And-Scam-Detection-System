"""
PhishGuard AI - DSA Module: Trie (Prefix / Keyword Tree)
Provides O(L) prefix, exact, and substring matching for:
  - Trusted sovereign and platform domains (.gov, .nic.in, google.com, etc.)
  - High-risk suspicious TLDs (.xyz, .top, .tk, etc.)
  - Phishing intent keywords (login, verify, banking, etc.)
  - Suspicious URL directory paths (/login.php, /cpanel/, etc.)
"""

from typing import Dict, Any, List, Optional, Set


class TrieNode:
    def __init__(self):
        self.children: Dict[str, "TrieNode"] = {}
        self.is_end_of_word: bool = False
        self.data: Dict[str, Any] = {}


class Trie:
    """
    Standard Trie data structure for fast string operations.
    Supports insert, exact search, prefix search, and tokenized text search.
    """

    def __init__(self):
        self.root = TrieNode()

    def insert(self, word: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Insert a word into the Trie with optional associated metadata."""
        if not word:
            return
        node = self.root
        for char in word.lower():
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True
        if data:
            node.data.update(data)

    def search_exact(self, word: str) -> Optional[Dict[str, Any]]:
        """Check if exact word exists in Trie. Returns metadata dict or None."""
        if not word:
            return None
        node = self.root
        for char in word.lower():
            if char not in node.children:
                return None
            node = node.children[char]
        return node.data if node.is_end_of_word else None

    def search_prefix(self, prefix: str) -> bool:
        """Check if any word in the Trie starts with the given prefix."""
        if not prefix:
            return False
        node = self.root
        for char in prefix.lower():
            if char not in node.children:
                return False
            node = node.children[char]
        return True

    def find_suffix_match(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Check if domain ends with any registered pattern (e.g., .gov.in, .nic.in).
        Splits domain by '.' and checks suffix combinations.
        """
        parts = domain.lower().split(".")
        for i in range(len(parts)):
            candidate = "." + ".".join(parts[i:])
            meta = self.search_exact(candidate)
            if meta is not None:
                return meta
        return None

    def find_keywords_in_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Scans text and returns all registered keywords found in the text.
        Uses sliding window search starting at each character.
        """
        if not text:
            return []
        text = text.lower()
        found: List[Dict[str, Any]] = []
        seen_words: Set[str] = set()

        n = len(text)
        for i in range(n):
            node = self.root
            j = i
            matched_chars = []
            while j < n and text[j] in node.children:
                node = node.children[text[j]]
                matched_chars.append(text[j])
                if node.is_end_of_word:
                    matched_word = "".join(matched_chars)
                    if matched_word not in seen_words:
                        seen_words.add(matched_word)
                        found.append({"word": matched_word, "position": i, **node.data})
                j += 1
        return found


# ─────────────────────────────────────────────────────────────────────────────
# PRE-POPULATED SECURITY TRIES
# ─────────────────────────────────────────────────────────────────────────────


def build_trusted_domain_trie() -> Trie:
    """Trie containing official sovereign domains and verified global platforms."""
    trie = Trie()

    # Government and Public Sovereign TLD suffixes
    gov_suffixes = [
        (".gov.in", "India Government"),
        (".nic.in", "National Informatics Centre India"),
        (".gov.uk", "United Kingdom Government"),
        (".gov.au", "Australia Government"),
        (".gov.sg", "Singapore Government"),
        (".gc.ca", "Canada Government"),
        (".gov.br", "Brazil Government"),
        (".go.jp", "Japan Government"),
        (".europa.eu", "European Union"),
        (".who.int", "World Health Organization"),
        (".un.org", "United Nations"),
        (".mil", "Military Agency"),
        (".edu", "Accredited Educational Institute"),
        (".ac.in", "India Academic Institute"),
        (".edu.au", "Australia Academic Institute"),
        (".ac.uk", "UK Academic Institute"),
        (".admin.ch", "Swiss Federal Administration"),
        (".gov", "United States / Sovereign Government"),
        (".res.in", "India Research Institute"),
        (".org.in", "India Registered Organisation"),
        (".co.in", "India Commercial Domain"),
    ]
    for suf, entity in gov_suffixes:
        trie.insert(
            suf,
            {
                "type": "GOVERNMENT",
                "entity": entity,
                "label": f"Official {entity} Domain",
            },
        )

    # Verified Global Platform Root Domains
    trusted_platforms = [
        # Google ecosystem
        ("google.com", "Google"),
        ("www.google.com", "Google"),
        ("accounts.google.com", "Google"),
        ("mail.google.com", "Google"),
        ("drive.google.com", "Google"),
        ("play.google.com", "Google"),
        ("docs.google.com", "Google"),
        # Microsoft ecosystem
        ("microsoft.com", "Microsoft"),
        ("login.microsoftonline.com", "Microsoft"),
        ("live.com", "Microsoft"),
        ("outlook.com", "Microsoft"),
        ("office.com", "Microsoft"),
        ("azure.com", "Microsoft"),
        ("teams.microsoft.com", "Microsoft"),
        # Apple
        ("apple.com", "Apple"),
        ("icloud.com", "Apple"),
        ("idmsa.apple.com", "Apple"),
        # Dev platforms
        ("github.com", "GitHub"),
        ("gitlab.com", "GitLab"),
        ("bitbucket.org", "Bitbucket"),
        # Amazon / AWS
        ("amazon.com", "Amazon"),
        ("aws.amazon.com", "Amazon AWS"),
        ("amazon.in", "Amazon India"),
        ("console.aws.amazon.com", "Amazon AWS"),
        # Payment platforms
        ("paypal.com", "PayPal"),
        ("www.paypal.com", "PayPal"),
        ("stripe.com", "Stripe"),
        ("razorpay.com", "Razorpay"),
        ("paytm.com", "Paytm"),
        ("phonepe.com", "PhonePe"),
        ("mobikwik.com", "MobiKwik"),
        ("freecharge.in", "FreeCharge"),
        # Indian government portals
        ("india.gov.in", "Indian Government Portal"),
        ("incometaxindiaefiling.gov.in", "Income Tax India"),
        ("incometax.gov.in", "Income Tax India"),
        ("irctc.co.in", "IRCTC Indian Railways"),
        ("digilocker.gov.in", "DigiLocker India"),
        ("uidai.gov.in", "UIDAI Aadhaar India"),
        ("npci.org.in", "NPCI UPI India"),
        ("epfindia.gov.in", "EPFO India"),
        ("passportindia.gov.in", "Passport Seva India"),
        ("mca.gov.in", "Ministry of Corporate Affairs India"),
        ("cowin.gov.in", "CoWIN Vaccination India"),
        ("umang.gov.in", "UMANG India"),
        # Indian banks
        ("sbi.co.in", "State Bank of India"),
        ("onlinesbi.sbi", "State Bank of India"),
        ("hdfcbank.com", "HDFC Bank"),
        ("netbanking.hdfcbank.com", "HDFC Bank"),
        ("icicibank.com", "ICICI Bank"),
        ("axisbank.com", "Axis Bank"),
        ("yesbank.in", "Yes Bank"),
        ("pnbindia.in", "Punjab National Bank"),
        ("bankofbaroda.in", "Bank of Baroda"),
        ("kotaksecurities.com", "Kotak Mahindra Bank"),
        ("kotak.com", "Kotak Mahindra Bank"),
        ("indusind.com", "IndusInd Bank"),
        ("federalbank.co.in", "Federal Bank India"),
        ("idfcfirstbank.com", "IDFC First Bank"),
        # Indian e-commerce
        ("flipkart.com", "Flipkart"),
        ("myntra.com", "Myntra"),
        ("snapdeal.com", "Snapdeal"),
        ("meesho.com", "Meesho"),
        ("nykaa.com", "Nykaa"),
        # Social & Media
        ("netflix.com", "Netflix"),
        ("facebook.com", "Meta / Facebook"),
        ("instagram.com", "Instagram"),
        ("whatsapp.com", "WhatsApp"),
        ("twitter.com", "X / Twitter"),
        ("x.com", "X / Twitter"),
        ("linkedin.com", "LinkedIn"),
        ("wikipedia.org", "Wikipedia"),
        ("youtube.com", "YouTube"),
        ("reddit.com", "Reddit"),
        ("discord.com", "Discord"),
        # Crypto (legitimate)
        ("binance.com", "Binance"),
        ("coinbase.com", "Coinbase"),
        ("kraken.com", "Kraken"),
        ("wazirx.com", "WazirX India"),
        ("coindcx.com", "CoinDCX India"),
    ]
    for domain, brand in trusted_platforms:
        trie.insert(
            domain,
            {
                "type": "TRUSTED_PLATFORM",
                "brand": brand,
                "label": f"Verified Authentic {brand} Platform",
            },
        )

    return trie


def build_suspicious_tld_trie() -> Trie:
    """Trie containing high-abuse, low-cost top-level domains frequently abused for phishing."""
    trie = Trie()
    suspicious_tlds = [
        # Historically free/abused Freenom TLDs
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        # High-abuse generic TLDs
        "xyz",
        "top",
        "click",
        "buzz",
        "fit",
        "surf",
        "rest",
        "bid",
        "work",
        "date",
        "faith",
        "men",
        "loan",
        "stream",
        "download",
        "racing",
        "review",
        "accountant",
        "science",
        "party",
        "gdn",
        "icu",
        "cam",
        "casa",
        "monster",
        "cfd",
        "sbs",
        "beauty",
        "hair",
        "skin",
        "quest",
        "cyou",
        "bond",
        "vip",
        "uno",
        "link",
        "cricket",
        # Recently weaponized TLDs
        "pw",
        "cc",
        "ws",
        "bz",
        "nu",
        # Google TLDs abused for phishing (look like file extensions)
        "zip",
        "mov",
        # Novelty / brand-confusion TLDs
        "lol",
        "dad",
        "phd",
        "prof",
        "esq",
        # Country TLDs commonly abused internationally
        "ru",
        "cn",
        "to",
    ]
    for tld in suspicious_tlds:
        trie.insert(
            f".{tld}", {"tld": tld, "severity": "MEDIUM", "risk": "HIGH_ABUSE_TLD"}
        )
    return trie


def build_phishing_keyword_trie() -> Trie:
    """Trie containing security, financial, and authentication urgency keywords."""
    trie = Trie()
    keywords = [
        # --- Authentication & Credential Harvesting ---
        ("login", "HIGH", "Credential harvesting trigger"),
        ("signin", "HIGH", "Credential harvesting trigger"),
        ("sign-in", "HIGH", "Credential harvesting trigger"),
        ("log-in", "HIGH", "Credential harvesting trigger"),
        ("logon", "HIGH", "Credential harvesting trigger"),
        ("password", "CRITICAL", "Password prompt in URL"),
        ("passwd", "CRITICAL", "Password prompt in URL"),
        ("credential", "CRITICAL", "Credential keyword in URL"),
        ("auth", "MEDIUM", "Authentication indicator"),
        ("authenticate", "MEDIUM", "Authentication indicator"),
        ("oauth", "LOW", "OAuth token indicator"),
        ("2fa", "MEDIUM", "Two-factor auth lure"),
        ("mfa", "MEDIUM", "Multi-factor auth lure"),
        ("totp", "MEDIUM", "TOTP code lure"),
        ("captcha", "LOW", "Captcha bypass indicator"),
        ("session", "MEDIUM", "Session token in URL"),
        ("token", "MEDIUM", "Auth token in URL"),
        ("api-key", "HIGH", "API key exposure in URL"),
        ("secret", "HIGH", "Secret key exposure in URL"),
        # --- Financial & Urgency ---
        ("verify", "HIGH", "Deceptive verification urge"),
        ("verification", "HIGH", "Deceptive verification urge"),
        ("validate", "HIGH", "Deceptive validation urge"),
        ("wallet", "HIGH", "Cryptocurrency wallet target"),
        ("banking", "HIGH", "Banking portal impersonation"),
        ("netbanking", "HIGH", "Net banking portal impersonation"),
        ("internet-banking", "HIGH", "Net banking portal impersonation"),
        ("account", "MEDIUM", "Account state trigger"),
        ("update", "MEDIUM", "Urgent update trigger"),
        ("secure", "MEDIUM", "Fake security assurance"),
        ("security", "MEDIUM", "Fake security assurance"),
        ("confirm", "MEDIUM", "Confirmation lure"),
        ("billing", "HIGH", "Billing scam indicator"),
        ("invoice", "MEDIUM", "Invoice lure"),
        ("payment", "HIGH", "Payment harvesting trigger"),
        ("refund", "HIGH", "Tax or refund scam lure"),
        ("tax-refund", "CRITICAL", "Tax refund phishing lure"),
        ("suspended", "HIGH", "Account suspension scare lure"),
        ("blocked", "HIGH", "Account blocked scare lure"),
        ("locked", "HIGH", "Account locked scare lure"),
        ("unlock", "HIGH", "Account unlock lure"),
        ("recover", "HIGH", "Account recovery lure"),
        ("recovery", "HIGH", "Account recovery lure"),
        ("kyc", "HIGH", "KYC compliance scam lure"),
        ("otp", "CRITICAL", "OTP harvesting lure"),
        ("support", "LOW", "Customer support lure"),
        ("helpdesk", "LOW", "Fake helpdesk lure"),
        ("alert", "MEDIUM", "Urgency alert lure"),
        ("urgent", "HIGH", "Urgency pressure tactic"),
        ("warning", "MEDIUM", "Fake warning lure"),
        ("limited-time", "HIGH", "Urgency pressure tactic"),
        ("expires", "MEDIUM", "Expiry urgency lure"),
        # --- Indian-Specific Scam Patterns ---
        ("aadhaar", "HIGH", "Aadhaar identity scam lure"),
        ("aadhar", "HIGH", "Aadhaar identity scam lure"),
        ("upi", "HIGH", "UPI payment scam lure"),
        ("fastag", "HIGH", "FASTag scam lure"),
        ("epf", "HIGH", "EPF/PF scam lure"),
        ("pf-balance", "HIGH", "PF balance scam lure"),
        ("lic", "HIGH", "LIC insurance scam lure"),
        ("pm-kisan", "HIGH", "PM Kisan subsidy scam lure"),
        ("itr", "HIGH", "Income Tax Return scam lure"),
        ("pan-card", "HIGH", "PAN card scam lure"),
        ("e-kyc", "HIGH", "e-KYC identity scam lure"),
        ("digilocker", "HIGH", "DigiLocker spoof lure"),
        ("irctc", "HIGH", "IRCTC booking scam"),
        ("ration-card", "HIGH", "Ration card scam lure"),
        ("subsidy", "HIGH", "Government subsidy scam"),
        ("sarkari", "MEDIUM", "Government scheme bait"),
        ("lottery", "CRITICAL", "Lottery scam lure"),
        ("winner", "HIGH", "Prize or lottery scam lure"),
        ("prize", "HIGH", "Prize scam lure"),
        ("cashback", "MEDIUM", "Cashback scam lure"),
        ("free-recharge", "HIGH", "Free recharge scam"),
        ("sim-block", "CRITICAL", "SIM block scare tactic"),
        ("trai", "HIGH", "TRAI impersonation scam"),
    ]
    for word, severity, desc in keywords:
        trie.insert(word, {"severity": severity, "description": desc})
    return trie


def build_phishing_paths_trie() -> Trie:
    """Trie containing known phishing kit and administrative exploit paths."""
    trie = Trie()
    paths = [
        # PHP credential harvesters
        ("/login.php", "CRITICAL", "Generic PHP credential harvester"),
        ("/signin.php", "CRITICAL", "Generic PHP credential harvester"),
        ("/submit.php", "CRITICAL", "Generic PHP form submit harvester"),
        ("/send.php", "HIGH", "Data exfiltration endpoint"),
        ("/gate.php", "CRITICAL", "Malware C2 gate endpoint"),
        ("/panel.php", "HIGH", "Phishing panel admin"),
        ("/post.php", "HIGH", "Data exfiltration endpoint"),
        ("/result.php", "HIGH", "Credential result dump"),
        ("/index.php", "LOW", "Generic PHP entry point"),
        # CMS exploits
        ("/wp-login.php", "MEDIUM", "WordPress admin login"),
        ("/wp-admin/", "LOW", "WordPress administrative area"),
        ("/xmlrpc.php", "MEDIUM", "WordPress XML-RPC exploit surface"),
        ("/wp-config.php", "CRITICAL", "WordPress config leak"),
        # Hosting panels
        ("/cpanel/", "MEDIUM", "cPanel management endpoint"),
        ("/webmail/", "MEDIUM", "Webmail harvesting endpoint"),
        ("/whm/", "MEDIUM", "WHM web host manager"),
        # Admin paths
        ("/admin/login", "MEDIUM", "Administrative login path"),
        ("/admin/", "LOW", "Administrative area"),
        ("/administrator/", "LOW", "Joomla administrative area"),
        ("/phpmyadmin/", "HIGH", "phpMyAdmin database exploit"),
        ("/pma/", "HIGH", "phpMyAdmin alias exploit"),
        # Traversal / RCE
        ("/cmd.exe", "CRITICAL", "Remote command execution path"),
        ("/etc/passwd", "CRITICAL", "Directory traversal indicator"),
        ("/.env", "CRITICAL", "Environment variables leak path"),
        ("/.git/", "HIGH", "Git repository exposure"),
        ("/.svn/", "HIGH", "SVN repository exposure"),
        ("/config.php", "CRITICAL", "PHP config file exposure"),
        ("/backup.zip", "HIGH", "Backup file exposure"),
        ("/db.sql", "CRITICAL", "Database dump exposure"),
        # Social engineering paths
        ("/.well-known/", "LOW", "Hidden configuration path"),
        ("/verify", "MEDIUM", "Verification lure path"),
        ("/confirm", "MEDIUM", "Confirmation lure path"),
        ("/secure/", "MEDIUM", "Fake secure area path"),
        ("/update/", "MEDIUM", "Update lure path"),
        ("/account/", "MEDIUM", "Account lure path"),
        ("/reset/", "MEDIUM", "Password reset lure"),
        ("/support/", "LOW", "Fake support path"),
        ("/helpdesk/", "LOW", "Fake helpdesk path"),
    ]
    for path, severity, desc in paths:
        trie.insert(path, {"severity": severity, "description": desc})
    return trie


# Singleton Trie instances
TRUSTED_DOMAIN_TRIE = build_trusted_domain_trie()
SUSPICIOUS_TLD_TRIE = build_suspicious_tld_trie()
PHISHING_KEYWORD_TRIE = build_phishing_keyword_trie()
PHISHING_PATHS_TRIE = build_phishing_paths_trie()
