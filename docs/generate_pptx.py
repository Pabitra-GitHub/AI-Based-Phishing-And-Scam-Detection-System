import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    # 16:9 Widescreen dimensions
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Theme Colors
    BG_COLOR = RGBColor(15, 23, 42)        # Slate 900
    CARD_BG = RGBColor(30, 41, 59)         # Slate 800
    CARD_BORDER = RGBColor(51, 65, 85)     # Slate 700
    TEXT_MAIN = RGBColor(248, 250, 252)    # Slate 50
    TEXT_MUTED = RGBColor(148, 163, 184)   # Slate 400
    TEXT_SUB = RGBColor(203, 213, 225)     # Slate 300
    ACCENT_BLUE = RGBColor(56, 189, 248)   # Sky 400
    ACCENT_GREEN = RGBColor(52, 211, 153)  # Emerald 400
    ACCENT_PURPLE = RGBColor(192, 132, 252)# Purple 400
    ACCENT_AMBER = RGBColor(251, 191, 36)  # Amber 400
    ACCENT_RED = RGBColor(248, 113, 113)   # Red 400

    def apply_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.fill.background()
        return bg

    def add_header(slide, slide_num, category, title, subtitle):
        apply_background(slide)

        # Top Bar Category Pill
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(8), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = f"🛡️ PHISHGUARD AI PLATFORM  |  {category.upper()}"
        p_cat.font.size = Pt(10)
        p_cat.font.bold = True
        p_cat.font.color.rgb = ACCENT_BLUE

        # Slide Number Pill (Right)
        num_box = slide.shapes.add_textbox(Inches(10.5), Inches(0.4), Inches(2), Inches(0.4))
        tf_num = num_box.text_frame
        p_num = tf_num.paragraphs[0]
        p_num.text = f"Slide {slide_num:02d} / 12"
        p_num.alignment = PP_ALIGN.RIGHT
        p_num.font.size = Pt(11)
        p_num.font.bold = True
        p_num.font.color.rgb = TEXT_MUTED

        # Slide Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.6))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title
        p_title.font.size = Pt(22)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_MAIN

        # Slide Subtitle
        sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.45), Inches(11.7), Inches(0.45))
        tf_sub = sub_box.text_frame
        tf_sub.word_wrap = True
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = subtitle
        p_sub.font.size = Pt(12)
        p_sub.font.color.rgb = TEXT_MUTED

    def add_card(slide, left, top, width, height, title, items, title_color=ACCENT_BLUE):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = CARD_BG
        shape.line.color.rgb = CARD_BORDER
        shape.line.width = Pt(1)

        tf = shape.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.25)
        tf.margin_bottom = Inches(0.25)

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.size = Pt(14)
        p0.font.bold = True
        p0.font.color.rgb = title_color
        p0.space_after = Pt(10)

        for item in items:
            p = tf.add_paragraph()
            p.text = f"•  {item}"
            p.font.size = Pt(11)
            p.font.color.rgb = TEXT_SUB
            p.space_after = Pt(6)

        return shape

    def add_image_placeholder(slide, left, top, width, height, title, description):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = RGBColor(18, 26, 43)
        shape.line.color.rgb = ACCENT_BLUE
        shape.line.width = Pt(1.5)

        tf = shape.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.3)
        tf.margin_right = Inches(0.3)
        tf.margin_top = Inches(0.3)

        p0 = tf.paragraphs[0]
        p0.text = f"🖼️ {title}"
        p0.alignment = PP_ALIGN.CENTER
        p0.font.size = Pt(13)
        p0.font.bold = True
        p0.font.color.rgb = ACCENT_BLUE
        p0.space_after = Pt(8)

        p1 = tf.add_paragraph()
        p1.text = description
        p1.alignment = PP_ALIGN.CENTER
        p1.font.size = Pt(10)
        p1.font.color.rgb = TEXT_MUTED

        return shape

    def set_notes(slide, text):
        notes_slide = slide.notes_slide
        tf = notes_slide.notes_text_frame
        tf.text = text

    # ==========================================
    # SLIDE 1: TITLE PAGE
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    apply_background(s1)

    tbox = s1.shapes.add_textbox(Inches(1), Inches(1.2), Inches(11.33), Inches(2.2))
    tf1 = tbox.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "MINOR PROJECT PRESENTATION  •  7TH SEMESTER"
    p.alignment = PP_ALIGN.CENTER
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = ACCENT_BLUE
    p.space_after = Pt(12)

    p2 = tf1.add_paragraph()
    p2.text = "PhishGuard AI"
    p2.alignment = PP_ALIGN.CENTER
    p2.font.size = Pt(44)
    p2.font.bold = True
    p2.font.color.rgb = TEXT_MAIN
    p2.space_after = Pt(10)

    p3 = tf1.add_paragraph()
    p3.text = "AI-Based Phishing & Scam Detection System via Multi-Layered Heuristics,\nDynamic Programming, and Supervised Machine Learning"
    p3.alignment = PP_ALIGN.CENTER
    p3.font.size = Pt(16)
    p3.font.color.rgb = ACCENT_BLUE

    # 3 Placeholder Cards
    c1 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.2), Inches(3.9), Inches(3.4), Inches(2.3))
    c1.fill.solid()
    c1.fill.fore_color.rgb = CARD_BG
    c1.line.color.rgb = CARD_BORDER
    tf_c1 = c1.text_frame
    tf_c1.margin_left = tf_c1.margin_right = Inches(0.2)
    tf_c1.paragraphs[0].text = "CANDIDATE DETAILS"
    tf_c1.paragraphs[0].font.size = Pt(10)
    tf_c1.paragraphs[0].font.bold = True
    tf_c1.paragraphs[0].font.color.rgb = ACCENT_BLUE
    p = tf_c1.add_paragraph()
    p.text = "Ch. Pabitra Kumar Nayak (Leader)\nReg No: 2301322088\nMahaprasad Paltasingh (2301322125)\nLaxmikanta Pradhan (2301322118)\nBikram Nayak (2301322079)"
    p.font.size = Pt(9.5)
    p.font.bold = False
    p.font.color.rgb = TEXT_MAIN

    c2 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(4.96), Inches(3.9), Inches(3.4), Inches(2.3))
    c2.fill.solid()
    c2.fill.fore_color.rgb = CARD_BG
    c2.line.color.rgb = CARD_BORDER
    tf_c2 = c2.text_frame
    tf_c2.margin_left = tf_c2.margin_right = Inches(0.2)
    tf_c2.paragraphs[0].text = "DEPARTMENT & PROGRAM"
    tf_c2.paragraphs[0].font.size = Pt(10)
    tf_c2.paragraphs[0].font.bold = True
    tf_c2.paragraphs[0].font.color.rgb = ACCENT_GREEN
    p = tf_c2.add_paragraph()
    p.text = "B.Tech Computer Science & Engineering"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_MAIN
    p = tf_c2.add_paragraph()
    p.text = "Einstein Academy of Technology & Management (EATM)\nBhubaneswar, Odisha"
    p.font.size = Pt(10.5)
    p.font.color.rgb = TEXT_MUTED

    c3 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.73), Inches(3.9), Inches(3.4), Inches(2.3))
    c3.fill.solid()
    c3.fill.fore_color.rgb = CARD_BG
    c3.line.color.rgb = CARD_BORDER
    tf_c3 = c3.text_frame
    tf_c3.margin_left = tf_c3.margin_right = Inches(0.2)
    tf_c3.paragraphs[0].text = "SUPERVISION & GUIDANCE"
    tf_c3.paragraphs[0].font.size = Pt(10)
    tf_c3.paragraphs[0].font.bold = True
    tf_c3.paragraphs[0].font.color.rgb = ACCENT_PURPLE
    p = tf_c3.add_paragraph()
    p.text = "[Project Supervisor / Guide]"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_MAIN
    p = tf_c3.add_paragraph()
    p.text = "Department of Computer Science & Engineering\nAcademic Session: 2025-2026"
    p.font.size = Pt(10.5)
    p.font.color.rgb = TEXT_MUTED

    set_notes(s1, "Good morning esteemed evaluators. Today I present PhishGuard AI, an intelligent cybersecurity defense system designed to counter zero-day phishing, credential harvesting, and deceptive URL spoofing using a hybrid paradigm of deterministic algorithms and supervised AI.")

    # ==========================================
    # SLIDE 2: THE PROBLEM
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    add_header(s2, 2, "Threat Landscape Analysis", "The Phishing Epidemic: Why Traditional Security Fails",
               "Over 3.4 billion malicious emails and fake portals appear daily. Attackers exploit algorithmic blindspots in static firewalls.")

    add_card(s2, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Modern Social Engineering Vectors", [
                 "Deceptive Homoglyphs: Substituting lookalike characters (e.g., paypa1.com, Cyrillic runes) tricking human visual perception.",
                 "DGA Botnets: Domain Generation Algorithms producing thousands of short-lived high-entropy domains (e.g., x9v8q-security.top).",
                 "SSRF Intranet Exploits: URLs targeting private subnets (192.168.1.1, 10.0.0.1) and AWS cloud metadata (169.254.169.254).",
                 "Credential Injection via @: Authority splitting to disguise malicious destinations (https://google.com@evil-vault.top/login).",
                 "Static Blacklist Lag: Public feeds (Google Safe Browsing) have a 24-48 hour delay; 82% of theft happens in hour 1."
             ], ACCENT_RED)

    add_image_placeholder(s2, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
                          "Traditional Blacklist Latency vs Zero-Day Threats",
                          "Infographic diagram showing traditional anti-phishing blacklists having a 24-48 hour delay window, leaving end users completely exposed during peak credential theft periods.")

    set_notes(s2, "Traditional security relies on public blacklists like Google Safe Browsing. However, blacklists have a 24-hour latency lag. When an attacker registers a brand-new typosquatted domain, blacklists are blind. PhishGuard AI solves this with real-time algorithmic inspection.")

    # ==========================================
    # SLIDE 3: PURPOSE & OBJECTIVES
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    add_header(s3, 3, "Vision & Core Philosophy", "Project Purpose & The Hybrid Defense Paradigm",
               "Bridging mathematical certainty with predictive machine intelligence for zero-day threat prevention.")

    add_card(s3, Inches(0.8), Inches(2.1), Inches(3.7), Inches(4.7),
             "Sub-150ms Instant Auditing", [
                 "Evaluates target URLs in real-time with zero dependency on third-party API rate limits.",
                 "Eliminates heavy multi-second headless browser overhead with fast socket verification.",
                 "In-memory model execution with zero cold-start latency.",
                 "End-to-end user evaluation completing in < 120ms."
             ], ACCENT_BLUE)

    add_card(s3, Inches(4.8), Inches(2.1), Inches(3.7), Inches(4.7),
             "Zero False Positives for Sovereign Sites", [
                 "Deterministic trust engine protecting official government portals (.gov, .nic.in, .gov.in).",
                 "Complex citizen service URLs bypass statistical noise and receive guaranteed clean status.",
                 "Verified brand platform certificates for tech ecosystems (Google, PayPal, Microsoft).",
                 "Authoritative whitelisting precedes ML inference."
             ], ACCENT_GREEN)

    add_card(s3, Inches(8.8), Inches(2.1), Inches(3.7), Inches(4.7),
             "Explainable Cybersecurity (XAI)", [
                 "Eliminates opaque 'black-box' verdicts with fully transparent reasoning.",
                 "Itemized triggered detection rules with severity ratings (Critical, High, Medium, Low).",
                 "Plain-English 'What this means' educational cards for every check.",
                 "Empowers non-technical users to understand the root deception."
             ], ACCENT_PURPLE)

    set_notes(s3, "Our core philosophy is that machine learning alone is insufficient for cybersecurity. ML is probabilistic, which means it can produce false positives on complex, valid government links. By pairing mathematical Data Structures and Algorithms with a trained ML classifier, we achieve both deterministic accuracy and zero-day pattern recognition.")

    # ==========================================
    # SLIDE 4: SYSTEM ARCHITECTURE
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    add_header(s4, 4, "System Architecture", "End-to-End Architectural Pipeline",
               "A decoupled, production-grade architecture combining React 18, FastAPI, and modular security services.")

    add_card(s4, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Multi-Tier Pipeline Components", [
                 "Client Presentation Layer: React 18, TypeScript, Tailwind CSS, Lucide icons, full-width responsive telemetry.",
                 "API Middleware (FastAPI): Asynchronous Python REST endpoints, strict Pydantic URL sanitation, and CORS guards.",
                 "Layer 1-3 Deterministic DSA Suite: Sovereign registry, Trie matching, Levenshtein DP homoglyphs, and Shannon entropy.",
                 "Layer 4 Network Auditor: Safe socket DNS resolution, active TLS certificate audit, and redirect cycle graph traversal.",
                 "Layer 5 AI Classifier: Scikit-learn Random Forest ensemble on 20+ extracted lexical feature vectors.",
                 "Persistence & Auth: SQLite database tracking historical scans and administrative audit logs with JWT auth."
             ], ACCENT_BLUE)

    add_image_placeholder(s4, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
                          "Technical Architecture & Data Flow Diagram",
                          "Flowchart tracing a URL request from the Frontend UI → FastAPI Router → Heuristic & DSA Pipeline → ML Engine → Composite Risk Scorer → Database & Client Response.")

    set_notes(s4, "When a user inputs a URL, it is routed through FastAPI. Before touching the machine learning model, the link passes through our deterministic safety layers: authoritative registries, dynamic programming edit distance, and safe-socket probes. The pipeline aggregates these signals into a unified risk score in under 150 milliseconds.")

    # ==========================================
    # SLIDE 5: DOMAIN VERIFICATION
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    add_header(s5, 5, "Layer 1 Defense", "Domain Verification & Sovereign Whitelist Protection",
               "Deterministic trust engineering eliminating false positive penalties on legitimate public and corporate platforms.")

    add_card(s5, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Sovereign Trust & Brand Verification", [
                 "Authoritative Sovereign Whitelist: Hardcoded pattern matching for sovereign extensions (.gov, .mil, .nic.in, .gov.in).",
                 "Guaranteed 0/100 Risk Score: Official citizen portals (e.g., india.gov.in) are mathematically protected from classification penalties.",
                 "Authentic Brand Infrastructure: Validates legitimate domains of major ecosystems (Google, PayPal, Microsoft, Apple).",
                 "Subdomain Spoofing Interception: Validates genuine infrastructure like accounts.google.com while blocking spoofed subdomains.",
                 "Why Whitelisting Must Precede ML: Government URLs feature lengthy queries and tokens that pure statistical models often mistake for threats."
             ], ACCENT_GREEN)

    add_image_placeholder(s5, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
                          "Verified Sovereign Govt Portal UI Badge",
                          "UI Screenshot of PhishGuard AI scanning 'https://india.gov.in' showing Verified Sovereign Govt Portal Badge and 0/100 Risk Score.")

    set_notes(s5, "Layer 1 handles domain verification. Pure machine learning models often penalize government portals because they have lengthy query parameters. PhishGuard AI solves this by recognizing authoritative sovereign extensions like .gov.in and .nic.in, immediately awarding them a zero risk score.")

    # ==========================================
    # SLIDE 6: DSA ENGINES
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    add_header(s6, 6, "Layer 2 Algorithmic Core", "Algorithmic Defense: Dynamic Programming & Trie Matching",
               "Applying foundational Computer Science data structures to detect typosquatting and deceptive lexical signatures.")

    add_card(s6, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Dynamic Programming: Levenshtein Distance", [
                 "Matrix-based minimal edit calculation (insertions, deletions, substitutions) between target domain and authentic brand names.",
                 "Homoglyph Normalization: Pre-processes visual runes (0 -> o, 1 -> l, vv -> w, @ -> a).",
                 "Detects sneaky impersonation domains like paypa1-security.com with an edit distance of 1.",
                 "Time complexity: O(M * N) with optimized 2-row rolling memory buffer."
             ], ACCENT_PURPLE)

    add_card(s6, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
             "Tokenized Prefix & Suffix Trie Engine", [
                 "High-speed Trie tree that searches sub-millisecond keyword registries regardless of dictionary scale.",
                 "O(L) time complexity where L is domain length (independent of word count).",
                 "Tokenizes urgent phishing keywords (login, verify, banking, wallet, update).",
                 "Simultaneously flags high-abuse top-level domains (.xyz, .top, .work, .icu, .tk)."
             ], ACCENT_BLUE)

    set_notes(s6, "Layer 2 implements foundational data structures. We use Dynamic Programming with Levenshtein distance and a confusables map to detect lookalike domains like 'paypa1'. Simultaneously, an O(L) Trie scans for high-risk phishing keywords and suspicious top-level domains in sub-millisecond time.")

    # ==========================================
    # SLIDE 7: ENTROPY & SSRF
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    add_header(s7, 7, "Layer 3 Mathematical Heuristics", "Advanced Heuristics: Shannon Entropy & SSRF Neutralization",
               "Information theory mathematics and CIDR subnet decomposition to prevent automated attacks and internal probing.")

    add_card(s7, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Shannon Information Entropy H(X)", [
                 "Formula: H(X) = - SUM [ P(x_i) * log2(P(x_i)) ]",
                 "Evaluates character distribution randomness across domain labels.",
                 "Catches automated Domain Generation Algorithms (DGA) used by botnets.",
                 "Normal readable domain (google.com): ~ 2.1 entropy.",
                 "Automated DGA domain (xk91m7b-pqz.biz): > 3.65 entropy -> FLAGGED as High-Entropy Threat."
             ], ACCENT_AMBER)

    add_card(s7, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
             "SSRF & Intranet Protection", [
                 "Prevents attackers from using PhishGuard as a proxy to attack internal infrastructure.",
                 "RFC-1918 Private Ranges: Blocks 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.",
                 "Loopback & Cloud Metadata: Blocks 127.0.0.1, localhost, and AWS metadata 169.254.169.254.",
                 "Credential Injection Defense: Detects and strips deceptive '@' symbol authority tricks."
             ], ACCENT_RED)

    set_notes(s7, "Malware botnets generate hundreds of random domains daily. We detect these mathematically using Claude Shannon's Information Entropy. Furthermore, PhishGuard protects local networks and cloud servers by decomposing IP addresses to block SSRF exploits.")

    # ==========================================
    # SLIDE 8: NETWORK SCANS
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    add_header(s8, 8, "Layer 4 Network Security", "Live Network Security Scans & Cryptographic Auditing",
               "Active socket probes verifying real-world host existence, SSL certificates, and redirect cloaking.")

    add_card(s8, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Active Network Probing Features", [
                 "Safe-Socket DNS Resolution: Resolves active A/AAAA records with strict 2.0-second safety timeout. Identifies dead NXDOMAIN sites immediately.",
                 "Active SSL/TLS Cryptographic Audit: Executes raw TLS handshakes over port 443 without downloading untrusted HTML or executable payloads.",
                 "Certificate Validity Audit: Verifies expiration dates, issuer authority, self-signed signatures, and cipher protocols.",
                 "Insecure HTTP Flagging: Flags plaintext port 80 links requesting login data.",
                 "Directed Graph Redirect Chain Tracing: Traverses HTTP 301/302 hops to reveal hidden final landing destinations."
             ], ACCENT_BLUE)

    add_image_placeholder(s8, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
                          "Live Redirect Chain & Network Details UI",
                          "Screenshot showing PhishGuard AI's redirect tracker UI with hop status codes (301 → 302 → 200), resolved host IP address, latency, and cryptographic protocol indicator.")

    set_notes(s8, "In Layer 4, we probe the live network safely. We establish a raw TLS handshake to verify that the website has a legitimate security certificate and trace redirect chains to uncover destinations attempting to conceal their true identity.")

    # ==========================================
    # SLIDE 9: MACHINE LEARNING
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    add_header(s9, 9, "Layer 5 Supervised AI", "Supervised Machine Learning & Feature Engineering",
               "Extracting 20+ lexical and structural vectors to classify zero-day campaign patterns.")

    add_card(s9, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "20+ Extracted Feature Vectors", [
                 "Structural Attributes: Total URL length, domain length, path depth, token count, subdomain count.",
                 "Lexical Frequencies: Count of hyphens (-), dots (.), underscores (_), digit-to-letter ratio.",
                 "Protocol Attributes: HTTPS flag, explicit non-standard ports, query string complexity.",
                 "Syntactic Anomalies: Embedded IP addresses, double-slash (//) redirect tricks, Shannon entropy.",
                 "Ensemble Classifier: Scikit-learn Random Forest / Gradient Boosted model loaded in-memory via Joblib."
             ], ACCENT_PURPLE)

    add_card(s9, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
             "Dual-Scoring Architecture", [
                 "1. ML Confidence Probability (0.0% - 100.0%): Pure statistical model probability based on learned lexical pattern vectors.",
                 "2. Composite Risk Score (0 - 100 Points): Weighted threat score fusing deterministic DSA penalties with ML probabilities.",
                 "Classification Thresholds:",
                 "  • SAFE: 0 - 29 (Clean verified domain)",
                 "  • SUSPICIOUS: 30 - 59 (Heuristic flags triggered)",
                 "  • HIGH RISK: 60 - 84 (Significant malicious indicators)",
                 "  • CRITICAL THREAT: 85 - 100 (Severe zero-day attack)"
             ], ACCENT_BLUE)

    set_notes(s9, "Layer 5 extracts over 20 lexical features from the URL. Our trained classifier calculates an ML confidence probability, which is then fused with the deterministic DSA rule penalties to generate the final composite risk score.")

    # ==========================================
    # SLIDE 10: USER INTERFACE
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    add_header(s10, 10, "Frontend Experience", "User Experience: Full-Width Telemetry & Explainable Cards",
               "A cyber defense dashboard built with React 18, Tailwind CSS, and edge-to-edge layout.")

    add_card(s10, Inches(0.8), Inches(2.1), Inches(5.6), Inches(4.7),
             "Key User Interface Innovations", [
                 "Interactive Semi-Circular Risk Gauge: Instant visual verdict with color-graded security states (Safe, Suspicious, High Risk, Critical).",
                 "Multi-Column Responsive DSA Matrix: 3-column responsive grid showcasing the status of all 5 core algorithmic checks side-by-side.",
                 "Explainable AI Reason Cards: Itemized list of triggered rules with severity tags (Critical, High, Medium, Low) and plain-English explanations.",
                 "Edge-to-Edge Screen Optimization: Fully responsive layout utilizing 100% of display width with zero wasted margins.",
                 "One-Click Sample Links: Instant testing for India.gov.in, Google, Typosquatting, and SSRF links."
             ], ACCENT_BLUE)

    add_image_placeholder(s10, Inches(6.8), Inches(2.1), Inches(5.7), Inches(4.7),
                          "Full-Screen Dashboard & Scanner Result UI",
                          "High-resolution screenshot showing the PhishGuard AI Scanner with Risk Gauge, Target URL bar, 3-column DSA Summary grid, and Triggered Detection Reason cards.")

    set_notes(s10, "Our user interface is designed like a modern security operations center. It provides full screen visibility, an interactive risk gauge, and clear itemized cards explaining exactly why a link is dangerous, demystifying cybersecurity for every user.")

    # ==========================================
    # SLIDE 11: GOVERNANCE & EVALUATION
    # ==========================================
    s11 = prs.slides.add_slide(blank_layout)
    add_header(s11, 11, "Enterprise Telemetry", "System Governance, Telemetry & Performance Evaluation",
               "Enterprise RBAC security, live audit logging, zero-downtime model updates, and empirical benchmarks.")

    add_card(s11, Inches(0.8), Inches(2.1), Inches(3.7), Inches(4.7),
             "Security & RBAC", [
                 "JWT session tokens & bcrypt password hashing.",
                 "Role-based access control protecting admin endpoints.",
                 "Live security audit stream logging client IP, action type, and timestamps.",
                 "Account activation toggle."
             ], ACCENT_GREEN)

    add_card(s11, Inches(4.8), Inches(2.1), Inches(3.7), Inches(4.7),
             "Zero-Downtime Operations", [
                 "Hot-Reload ML Model: Admins can reload updated model artifacts directly from the UI without taking down the server.",
                 "Seamless zero-downtime deployment of retrained threat models on the fly.",
                 "Real-time model version telemetry tracking."
             ], ACCENT_PURPLE)

    add_card(s11, Inches(8.8), Inches(2.1), Inches(3.7), Inches(4.7),
             "Empirical Benchmarks", [
                 "Latency: Averaging < 120ms total end-to-end audit time.",
                 "Trie Speed: < 0.5ms per tokenized registry lookup.",
                 "Accuracy: 0% false positives on sovereign public portals; 99%+ on verified phishing sets.",
                 "High throughput async concurrency."
             ], ACCENT_BLUE)

    set_notes(s11, "PhishGuard AI is built for enterprise operations. It includes JWT authentication, complete audit logging, and a zero-downtime model hot-reload feature. Benchmarks confirm sub-120 millisecond end-to-end scan times with 0% false positives on sovereign domains.")

    # ==========================================
    # SLIDE 12: CONCLUSION & THANK YOU
    # ==========================================
    s12 = prs.slides.add_slide(blank_layout)
    apply_background(s12)

    top_box = s12.shapes.add_textbox(Inches(1), Inches(0.9), Inches(11.33), Inches(1.8))
    tf12 = top_box.text_frame
    tf12.word_wrap = True

    p = tf12.paragraphs[0]
    p.text = "DEFENSE & VIVA EVALUATION CONCLUDED"
    p.alignment = PP_ALIGN.CENTER
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN
    p.space_after = Pt(10)

    p2 = tf12.add_paragraph()
    p2.text = "Thank You!"
    p2.alignment = PP_ALIGN.CENTER
    p2.font.size = Pt(46)
    p2.font.bold = True
    p2.font.color.rgb = TEXT_MAIN
    p2.space_after = Pt(8)

    p3 = tf12.add_paragraph()
    p3.text = "PhishGuard AI successfully demonstrates that combining deterministic Data Structures with Machine Learning\nproduces a fast, explainable, and reliable defense against modern cyber scams."
    p3.alignment = PP_ALIGN.CENTER
    p3.font.size = Pt(15)
    p3.font.color.rgb = TEXT_MUTED

    # 3 Bottom Summary Cards
    c1 = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.2), Inches(3.6), Inches(3.4), Inches(2.2))
    c1.fill.solid()
    c1.fill.fore_color.rgb = CARD_BG
    c1.line.color.rgb = CARD_BORDER
    tf_c1 = c1.text_frame
    tf_c1.margin_left = tf_c1.margin_right = Inches(0.2)
    tf_c1.paragraphs[0].text = "SOURCE CODE"
    tf_c1.paragraphs[0].font.size = Pt(10)
    tf_c1.paragraphs[0].font.bold = True
    tf_c1.paragraphs[0].font.color.rgb = ACCENT_BLUE
    p = tf_c1.add_paragraph()
    p.text = "GitHub Repository"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_MAIN
    p = tf_c1.add_paragraph()
    p.text = "[github.com/your-username/PhishGuard-AI]"
    p.font.size = Pt(10)
    p.font.color.rgb = TEXT_MUTED

    c2 = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(4.96), Inches(3.6), Inches(3.4), Inches(2.2))
    c2.fill.solid()
    c2.fill.fore_color.rgb = CARD_BG
    c2.line.color.rgb = CARD_BORDER
    tf_c2 = c2.text_frame
    tf_c2.margin_left = tf_c2.margin_right = Inches(0.2)
    tf_c2.paragraphs[0].text = "DEPLOYMENT"
    tf_c2.paragraphs[0].font.size = Pt(10)
    tf_c2.paragraphs[0].font.bold = True
    tf_c2.paragraphs[0].font.color.rgb = ACCENT_GREEN
    p = tf_c2.add_paragraph()
    p.text = "Live Web Application"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_MAIN
    p = tf_c2.add_paragraph()
    p.text = "UI: http://localhost:5173\nAPI: http://127.0.0.1:8000/docs"
    p.font.size = Pt(10)
    p.font.color.rgb = TEXT_MUTED

    c3 = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.73), Inches(3.6), Inches(3.4), Inches(2.2))
    c3.fill.solid()
    c3.fill.fore_color.rgb = CARD_BG
    c3.line.color.rgb = CARD_BORDER
    tf_c3 = c3.text_frame
    tf_c3.margin_left = tf_c3.margin_right = Inches(0.2)
    tf_c3.paragraphs[0].text = "CONTACT & VIVA"
    tf_c3.paragraphs[0].font.size = Pt(10)
    tf_c3.paragraphs[0].font.bold = True
    tf_c3.paragraphs[0].font.color.rgb = ACCENT_PURPLE
    p = tf_c3.add_paragraph()
    p.text = "Candidate Defense"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = TEXT_MAIN
    p = tf_c3.add_paragraph()
    p.text = "[Your Email Address]\nB.Tech Computer Science"
    p.font.size = Pt(10)
    p.font.color.rgb = TEXT_MUTED

    # Bottom Call to Action
    cta_box = s12.shapes.add_textbox(Inches(1), Inches(6.2), Inches(11.33), Inches(0.6))
    tf_cta = cta_box.text_frame
    p_cta = tf_cta.paragraphs[0]
    p_cta.text = "Questions, Feedback & Discussion Invited"
    p_cta.alignment = PP_ALIGN.CENTER
    p_cta.font.size = Pt(16)
    p_cta.font.bold = True
    p_cta.font.color.rgb = ACCENT_BLUE

    set_notes(s12, "In conclusion, PhishGuard AI proves that combining deterministic data structures with machine learning provides a fast, explainable, and reliable defense against zero-day phishing. Thank you for your time, and I welcome your questions and evaluation.")

    # Save output
    output_path = os.path.join(os.path.dirname(__file__), "PhishGuard_AI_Presentation.pptx")
    prs.save(output_path)
    print(f"Presentation successfully saved to: {output_path}")

if __name__ == "__main__":
    create_presentation()
