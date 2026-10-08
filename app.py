from flask import Flask, jsonify, request, render_template_string
import requests
import feedparser
from urllib.parse import quote_plus
from datetime import datetime

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

CISA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_CATALOG_URL = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)

GOOGLE_NEWS_RSS = (
    "https://news.google.com/rss/search?q={query}"
    "&hl=en-IN&gl=IN&ceid=IN:en"
)

HEADERS = {
    "User-Agent": "SentinelOSINT-Student-Project/3.0"
}


# ============================================================
# GET CISA KEV DATA
# ============================================================

def get_cisa_data():

    try:

        response = requests.get(
            CISA_URL,
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()

        return response.json()

    except Exception as e:

        print("CISA ERROR:", e)

        return {
            "catalogVersion": "",
            "dateReleased": "",
            "count": 0,
            "vulnerabilities": []
        }


# ============================================================
# THREAT CLASSIFICATION
# ============================================================

def classify_threat(item):

    ransomware = str(
        item.get("knownRansomwareCampaignUse", "")
    ).lower()

    description = str(
        item.get("shortDescription", "")
    ).lower()

    name = str(
        item.get("vulnerabilityName", "")
    ).lower()

    text = description + " " + name

    if ransomware == "known":
        return "Critical"

    if any(
        word in text
        for word in [
            "remote code execution",
            "command injection",
            "authentication bypass",
            "privilege escalation"
        ]
    ):
        return "High"

    return "Medium"


# ============================================================
# CATEGORY
# ============================================================

def get_category(item):

    ransomware = str(
        item.get("knownRansomwareCampaignUse", "")
    ).lower()

    description = str(
        item.get("shortDescription", "")
    ).lower()

    name = str(
        item.get("vulnerabilityName", "")
    ).lower()

    text = description + " " + name

    if ransomware == "known":
        return "Ransomware"

    if "phishing" in text:
        return "Phishing"

    if "malware" in text:
        return "Malware"

    if "remote code execution" in text:
        return "Remote Code Execution"

    if "authentication" in text:
        return "Authentication"

    if "privilege escalation" in text:
        return "Privilege Escalation"

    if "injection" in text:
        return "Injection"

    return "Vulnerability"


# ============================================================
# PREPARE CISA THREATS
# ============================================================

def prepare_threats():

    data = get_cisa_data()

    threats = []

    for item in data.get("vulnerabilities", []):

        threat = {

            "cve": item.get("cveID", ""),

            "vendor": item.get(
                "vendorProject",
                "Unknown"
            ),

            "product": item.get(
                "product",
                "Unknown"
            ),

            "name": item.get(
                "vulnerabilityName",
                "Unknown Vulnerability"
            ),

            "description": item.get(
                "shortDescription",
                ""
            ),

            "action": item.get(
                "requiredAction",
                ""
            ),

            "notes": item.get(
                "notes",
                ""
            ),

            "dateAdded": item.get(
                "dateAdded",
                ""
            ),

            "dueDate": item.get(
                "dueDate",
                ""
            ),

            "ransomware": item.get(
                "knownRansomwareCampaignUse",
                "Unknown"
            ),

            "severity": classify_threat(item),

            "category": get_category(item),

            "source": "CISA KEV",

            "sourceUrl": CISA_CATALOG_URL
        }

        threats.append(threat)

    return threats


# ============================================================
# GOOGLE NEWS CYBER THREAT SEARCH
# ============================================================

CYBER_KEYWORDS = [

    "cyberattack",
    "cyber attack",
    "cybersecurity",
    "ransomware",
    "phishing",
    "malware",
    "data breach",
    "data breach",
    "hacking",
    "hacked",
    "cybercrime",
    "credential theft",
    "identity theft",
    "ddos",
    "denial of service",
    "exploit",
    "vulnerability",
    "security breach",
    "cyber threat",
    "cyber fraud",
    "online fraud",
    "computer virus",
    "trojan",
    "spyware",
    "botnet"
]


# ============================================================
# DETECT CYBER THREAT
# ============================================================

def is_cyber_threat(article):

    title = str(
        article.get("title", "")
    ).lower()

    description = str(
        article.get("description", "")
    ).lower()

    text = title + " " + description

    for keyword in CYBER_KEYWORDS:

        if keyword in text:
            return True

    return False


# ============================================================
# CLASSIFY NEWS THREAT
# ============================================================

def classify_news_threat(article):

    text = (
        str(article.get("title", "")) +
        " " +
        str(article.get("description", ""))
    ).lower()

    if "ransomware" in text:
        return "Ransomware"

    if "phishing" in text:
        return "Phishing"

    if "malware" in text:
        return "Malware"

    if "data breach" in text or "security breach" in text:
        return "Data Breach"

    if "ddos" in text or "denial of service" in text:
        return "DDoS"

    if "vulnerability" in text or "exploit" in text:
        return "Vulnerability"

    if "hacking" in text or "hacked" in text:
        return "Hacking"

    if "cyber fraud" in text or "online fraud" in text:
        return "Cyber Fraud"

    if "cybercrime" in text:
        return "Cybercrime"

    return "Cybersecurity"


# ============================================================
# NEWS SEVERITY
# ============================================================

def news_severity(article):

    text = (
        str(article.get("title", "")) +
        " " +
        str(article.get("description", ""))
    ).lower()

    if any(
        word in text
        for word in [
            "ransomware",
            "data breach",
            "critical vulnerability",
            "major cyberattack",
            "large-scale attack"
        ]
    ):
        return "Critical"

    if any(
        word in text
        for word in [
            "cyberattack",
            "hacked",
            "malware",
            "phishing",
            "exploit",
            "security breach"
        ]
    ):
        return "High"

    return "Medium"


# ============================================================
# GOOGLE NEWS FUNCTION
# ============================================================

def get_news(query, limit=30):

    try:

        encoded_query = quote_plus(query)

        url = GOOGLE_NEWS_RSS.format(
            query=encoded_query
        )

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=20
        )

        response.raise_for_status()

        feed = feedparser.parse(
            response.content
        )

        articles = []

        for entry in feed.entries[:limit]:

            article = {

                "title": entry.get(
                    "title",
                    "Untitled"
                ),

                "link": entry.get(
                    "link",
                    ""
                ),

                "published": entry.get(
                    "published",
                    ""
                ),

                "source": (
                    entry.get(
                        "source",
                        {}
                    ).get(
                        "title",
                        "Google News"
                    )
                    if isinstance(
                        entry.get("source", {}),
                        dict
                    )
                    else "Google News"
                ),

                "description": entry.get(
                    "summary",
                    ""
                )
            }

            articles.append(article)

        return articles

    except Exception as e:

        print("NEWS ERROR:", e)

        return []


# ============================================================
# LOCATION CYBER THREAT SEARCH
# ============================================================

def get_location_threats(location):

    threat_queries = [

        f'"{location}" ransomware',

        f'"{location}" cyberattack',

        f'"{location}" phishing',

        f'"{location}" malware',

        f'"{location}" "data breach"',

        f'"{location}" hacking',

        f'"{location}" cybercrime',

        f'"{location}" vulnerability',

        f'"{location}" "security breach"',

        f'"{location}" "cyber fraud"',

        f'"{location}" "cyber threat"'
    ]

    all_articles = []

    seen_links = set()

    for query in threat_queries:

        articles = get_news(
            query,
            limit=10
        )

        for article in articles:

            link = article.get(
                "link",
                ""
            )

            if link in seen_links:
                continue

            if not is_cyber_threat(article):
                continue

            seen_links.add(link)

            article["location"] = location

            article["category"] = (
                classify_news_threat(
                    article
                )
            )

            article["severity"] = (
                news_severity(
                    article
                )
            )

            article["intelligenceType"] = (
                "Public Cyber Threat Report"
            )

            all_articles.append(
                article
            )

    return all_articles


# ============================================================
# FIND SINGLE CISA THREAT
# ============================================================

def find_threat(cve):

    threats = prepare_threats()

    for threat in threats:

        if threat["cve"].lower() == cve.lower():

            return threat

    return None


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template_string(
        HTML_PAGE
    )


# ============================================================
# CISA THREATS API
# ============================================================

@app.route("/api/threats")
def api_threats():

    threats = prepare_threats()

    return jsonify({

        "source": "CISA KEV",

        "sourceUrl": CISA_CATALOG_URL,

        "total_threats": len(threats),

        "threats": threats
    })


# ============================================================
# SEARCH API
# ============================================================

@app.route("/api/search")
def api_search():

    query = request.args.get(
        "q",
        ""
    ).strip()

    mode = request.args.get(
        "mode",
        "cisa"
    )

    if not query:

        return jsonify([])

    # --------------------------------------------------------
    # CISA SEARCH
    # --------------------------------------------------------

    if mode == "cisa":

        threats = prepare_threats()

        query_lower = query.lower()

        results = []

        for threat in threats:

            searchable = " ".join([

                threat["cve"],

                threat["vendor"],

                threat["product"],

                threat["name"],

                threat["description"],

                threat["action"],

                threat["notes"],

                threat["category"]

            ]).lower()

            if query_lower in searchable:

                results.append(threat)

        return jsonify(results)


    # --------------------------------------------------------
    # GLOBAL CYBER NEWS SEARCH
    # --------------------------------------------------------

    if mode == "global":

        articles = get_news(
            query,
            limit=30
        )

        cyber_articles = []

        for article in articles:

            if not is_cyber_threat(
                article
            ):
                continue

            article["category"] = (
                classify_news_threat(
                    article
                )
            )

            article["severity"] = (
                news_severity(
                    article
                )
            )

            article["intelligenceType"] = (
                "Public Cyber Threat Report"
            )

            cyber_articles.append(
                article
            )

        return jsonify(
            cyber_articles
        )


    # --------------------------------------------------------
    # LOCATION SEARCH
    # --------------------------------------------------------

    if mode == "location":

        results = get_location_threats(
            query
        )

        return jsonify(results)


    return jsonify([])


# ============================================================
# SINGLE THREAT API
# ============================================================

@app.route("/api/threat/<cve>")
def api_single_threat(cve):

    threat = find_threat(cve)

    if not threat:

        return jsonify({
            "error": "Threat not found"
        }), 404

    return jsonify(threat)


# ============================================================
# NEWS API
# ============================================================

@app.route("/api/news")
def api_news():

    query = request.args.get(
        "q",
        "cybersecurity"
    )

    articles = get_news(
        query,
        limit=20
    )

    return jsonify(articles)


# ============================================================
# HTML DASHBOARD
# ============================================================

HTML_PAGE = r'''
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>SentinelOSINT</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #07111f;

    color: #e5e7eb;
}


/* SIDEBAR */

.sidebar {

    position: fixed;

    left: 0;
    top: 0;
    bottom: 0;

    width: 240px;

    background: #0b1628;

    border-right: 1px solid #1e293b;

    padding: 25px 15px;
}

.logo {

    font-size: 22px;

    font-weight: bold;

    margin-bottom: 30px;

    color: #38bdf8;
}

.logo span {

    color: white;
}

.nav {

    padding: 12px;

    margin: 7px 0;

    border-radius: 8px;

    cursor: pointer;

    color: #94a3b8;
}

.nav:hover {

    background: #16243a;

    color: white;
}

.nav.active {

    background: #1e3a5f;

    color: #38bdf8;
}


/* MAIN */

.main {

    margin-left: 240px;

    padding: 25px;
}


/* HEADER */

.header {

    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 25px;
}

.header h1 {

    margin: 0;

    font-size: 27px;
}

.refresh {

    background: #0284c7;

    border: none;

    padding: 10px 18px;

    border-radius: 7px;

    color: white;

    cursor: pointer;
}

.refresh:hover {

    background: #0369a1;
}


/* STATS */

.stats {

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 15px;

    margin-bottom: 25px;
}

.stat {

    background: #0c1a2d;

    border: 1px solid #1e293b;

    border-radius: 10px;

    padding: 20px;
}

.stat-title {

    color: #94a3b8;

    font-size: 13px;
}

.stat-value {

    font-size: 28px;

    font-weight: bold;

    margin-top: 8px;
}


/* PANEL */

.panel {

    background: #0c1a2d;

    border: 1px solid #1e293b;

    border-radius: 10px;

    padding: 20px;

    margin-bottom: 20px;
}

.panel h2 {

    margin-top: 0;
}


/* SEARCH */

.search-area {

    display: flex;

    gap: 10px;

    margin-bottom: 20px;
}

input,
select {

    background: #07111f;

    color: white;

    border: 1px solid #334155;

    border-radius: 7px;

    padding: 11px;

    flex: 1;
}

button {

    border: none;

    border-radius: 7px;

    padding: 10px 16px;

    cursor: pointer;
}


/* THREATS */

.threat {

    border: 1px solid #26364c;

    border-radius: 9px;

    padding: 15px;

    margin-bottom: 10px;

    cursor: pointer;

    background: #0a1728;
}

.threat:hover {

    border-color: #38bdf8;

    background: #0e1f34;
}

.threat-top {

    display: flex;

    justify-content: space-between;

    gap: 10px;
}

.cve {

    color: #38bdf8;

    font-weight: bold;
}

.badge {

    padding: 4px 9px;

    border-radius: 20px;

    font-size: 11px;
}

.critical {

    background: #7f1d1d;

    color: #fecaca;
}

.high {

    background: #78350f;

    color: #fed7aa;
}

.medium {

    background: #164e63;

    color: #a5f3fc;
}

.threat-title {

    font-weight: bold;

    margin-top: 8px;
}

.threat-description {

    color: #94a3b8;

    font-size: 13px;

    margin-top: 7px;
}

.meta {

    color: #64748b;

    font-size: 12px;

    margin-top: 8px;
}


/* CHART */

.chart-row {

    margin-bottom: 12px;
}

.chart-label {

    display: flex;

    justify-content: space-between;

    margin-bottom: 4px;

    font-size: 13px;
}

.bar {

    height: 9px;

    background: #1e293b;

    border-radius: 10px;

    overflow: hidden;
}

.bar-fill {

    height: 100%;

    background: #38bdf8;
}


/* MODAL */

.modal {

    display: none;

    position: fixed;

    inset: 0;

    background: rgba(
        0,
        0,
        0,
        0.75
    );

    align-items: center;

    justify-content: center;

    padding: 20px;

    z-index: 100;
}

.modal-content {

    width: min(
        850px,
        100%
    );

    max-height: 90vh;

    overflow-y: auto;

    background: #0b1628;

    border: 1px solid #334155;

    border-radius: 12px;

    padding: 25px;
}

.close {

    float: right;

    font-size: 25px;

    cursor: pointer;
}

.detail {

    margin-top: 15px;

    padding: 13px;

    background: #07111f;

    border-radius: 7px;
}

.detail-label {

    color: #64748b;

    font-size: 12px;

    margin-bottom: 4px;
}

.news-card {

    border: 1px solid #26364c;

    border-radius: 9px;

    padding: 15px;

    margin-bottom: 10px;

    background: #0a1728;
}

.news-card a {

    color: #38bdf8;

    text-decoration: none;

    font-weight: bold;
}

.news-meta {

    color: #64748b;

    font-size: 12px;

    margin-top: 7px;
}

.empty {

    color: #94a3b8;

    padding: 20px;

    text-align: center;
}


/* RESPONSIVE */

@media(max-width: 900px) {

    .sidebar {

        width: 190px;
    }

    .main {

        margin-left: 190px;
    }

    .stats {

        grid-template-columns:
            repeat(2, 1fr);
    }
}

@media(max-width: 600px) {

    .sidebar {

        position: static;

        width: 100%;
    }

    .main {

        margin-left: 0;
    }

    .stats {

        grid-template-columns: 1fr;
    }

    .search-area {

        flex-direction: column;
    }
}

</style>

</head>


<body>


<!-- SIDEBAR -->

<div class="sidebar">

    <div class="logo">
        Sentinel<span>OSINT</span>
    </div>

    <div
        class="nav active"
        onclick="showView('dashboard')"
    >
        Dashboard
    </div>

    <div
        class="nav"
        onclick="showView('threats')"
    >
        Threat Intelligence
    </div>

    <div
        class="nav"
        onclick="showView('global')"
    >
        Global Intelligence
    </div>

    <div
        class="nav"
        onclick="showView('location')"
    >
        Location Search
    </div>

    <div
        class="nav"
        onclick="showView('analytics')"
    >
        Threat Analytics
    </div>

    <div
        class="nav"
        onclick="showView('sources')"
    >
        Intelligence Sources
    </div>

</div>


<!-- MAIN -->

<div class="main">


<!-- DASHBOARD -->

<section id="dashboardView">

    <div class="header">

        <div>

            <h1>
                Threat Intelligence Center
            </h1>

            <div class="meta">
                Public Cyber Threat Intelligence
            </div>

        </div>

        <button
            class="refresh"
            onclick="loadDashboard()"
        >
            Refresh
        </button>

    </div>


    <div class="stats">

        <div class="stat">

            <div class="stat-title">
                Total Threats
            </div>

            <div
                class="stat-value"
                id="total"
            >
                -
            </div>

        </div>


        <div class="stat">

            <div class="stat-title">
                Critical
            </div>

            <div
                class="stat-value"
                id="critical"
            >
                -
            </div>

        </div>


        <div class="stat">

            <div class="stat-title">
                High Risk
            </div>

            <div
                class="stat-value"
                id="high"
            >
                -
            </div>

        </div>


        <div class="stat">

            <div class="stat-title">
                Ransomware
            </div>

            <div
                class="stat-value"
                id="ransomware"
            >
                -
            </div>

        </div>

    </div>


    <div class="panel">

        <h2>
            Latest Threat Intelligence
        </h2>

        <div
            id="latestThreats"
        ></div>

    </div>

</section>


<!-- THREAT INTELLIGENCE -->

<section
    id="threatsView"
    style="display:none"
>

    <div class="header">

        <h1>
            Threat Intelligence
        </h1>

    </div>


    <div class="panel">

        <div class="search-area">

            <input
                id="cisaSearch"
                placeholder=
                "Search CVE, ransomware, Microsoft, phishing..."
            >

            <button
                onclick="searchCISA()"
                class="refresh"
            >
                Search
            </button>

        </div>

        <div
            id="cisaResults"
        ></div>

    </div>

</section>


<!-- GLOBAL -->

<section
    id="globalView"
    style="display:none"
>

    <div class="header">

        <h1>
            Global Cyber Intelligence
        </h1>

    </div>


    <div class="panel">

        <div class="search-area">

            <input
                id="globalSearch"
                placeholder=
                "Search ransomware, phishing, cyberattack..."
            >

            <button
                onclick="searchGlobal()"
                class="refresh"
            >
                Search
            </button>

        </div>

        <div
            id="globalResults"
        ></div>

    </div>

</section>


<!-- LOCATION -->

<section
    id="locationView"
    style="display:none"
>

    <div class="header">

        <div>

            <h1>
                Location-Based Cyber Threat Intelligence
            </h1>

            <div class="meta">
                Search public cybersecurity reports
                related to a specific location.
            </div>

        </div>

    </div>


    <div class="panel">

        <div class="search-area">

            <input
                id="locationSearch"
                placeholder=
                "Example: Navi Mumbai"
            >

            <button
                onclick="searchLocation()"
                class="refresh"
            >
                Search Threats
            </button>

        </div>


        <div id="locationInfo"></div>

        <div
            id="locationResults"
        ></div>

    </div>

</section>


<!-- ANALYTICS -->

<section
    id="analyticsView"
    style="display:none"
>

    <div class="header">

        <h1>
            Threat Analytics
        </h1>

    </div>


    <div class="panel">

        <h2>
            Severity Distribution
        </h2>

        <div id="severityChart"></div>

    </div>


    <div class="panel">

        <h2>
            Threat Categories
        </h2>

        <div id="categoryChart"></div>

    </div>

</section>


<!-- SOURCES -->

<section
    id="sourcesView"
    style="display:none"
>

    <div class="header">

        <h1>
            Intelligence Sources
        </h1>

    </div>


    <div class="panel">

        <h2>
            CISA KEV
        </h2>

        <p>
            Known Exploited Vulnerabilities
            Catalog.
        </p>

        <p>
            Provides vulnerabilities that have
            been exploited in the wild.
        </p>

        <a
            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            target="_blank"
        >
            Open CISA KEV
        </a>

    </div>


    <div class="panel">

        <h2>
            Google News
        </h2>

        <p>
            Used by SentinelOSINT to collect
            publicly reported cybersecurity
            information.
        </p>

        <p>
            News results are treated as
            public intelligence leads, not
            automatically verified incidents.
        </p>

    </div>

</section>


</div>


<!-- MODAL -->

<div
    class="modal"
    id="modal"
    onclick="closeModal(event)"
>

    <div
        class="modal-content"
        onclick="event.stopPropagation()"
    >

        <span
            class="close"
            onclick="hideModal()"
        >
            ×
        </span>

        <div id="modalContent"></div>

    </div>

</div>


<script>

let allThreats = [];


/* ============================================================
   NAVIGATION
   ============================================================ */

function showView(view) {

    const views = [

        "dashboard",
        "threats",
        "global",
        "location",
        "analytics",
        "sources"

    ];

    views.forEach(
        name => {

            const element =
                document.getElementById(
                    name + "View"
                );

            if (element) {

                element.style.display =
                    name === view
                        ? "block"
                        : "none";
            }

        }
    );


    document
        .querySelectorAll(".nav")
        .forEach(
            nav => nav.classList.remove(
                "active"
            )
        );


    event.currentTarget.classList.add(
        "active"
    );


    if (view === "analytics") {

        renderAnalytics();
    }

}


/* ============================================================
   LOAD DASHBOARD
   ============================================================ */

async function loadDashboard() {

    try {

        const response =
            await fetch(
                "/api/threats"
            );

        const data =
            await response.json();

        allThreats =
            data.threats || [];


        document.getElementById(
            "total"
        ).textContent =
            allThreats.length;


        document.getElementById(
            "critical"
        ).textContent =
            allThreats.filter(
                t =>
                    t.severity ===
                    "Critical"
            ).length;


        document.getElementById(
            "high"
        ).textContent =
            allThreats.filter(
                t =>
                    t.severity ===
                    "High"
            ).length;


        document.getElementById(
            "ransomware"
        ).textContent =
            allThreats.filter(
                t =>
                    String(
                        t.ransomware
                    ).toLowerCase()
                    === "known"
            ).length;


        renderThreats(
            allThreats.slice(
                0,
                15
            ),
            "latestThreats"
        );

    }

    catch(error) {

        console.error(error);

    }

}


/* ============================================================
   RENDER CISA THREATS
   ============================================================ */

function renderThreats(
    threats,
    containerId
) {

    const container =
        document.getElementById(
            containerId
        );


    if (!threats.length) {

        container.innerHTML =
            '<div class="empty">' +
            'No threats found.' +
            '</div>';

        return;
    }


    container.innerHTML =
        threats.map(
            threat => `

            <div
                class="threat"
                onclick="openThreat(
                    '${threat.cve}'
                )"
            >

                <div class="threat-top">

                    <div class="cve">
                        ${escapeHtml(
                            threat.cve
                        )}
                    </div>

                    <span
                        class="badge
                        ${threat.severity.toLowerCase()}"
                    >
                        ${escapeHtml(
                            threat.severity
                        )}
                    </span>

                </div>


                <div class="threat-title">
                    ${escapeHtml(
                        threat.name
                    )}
                </div>


                <div class="threat-description">
                    ${escapeHtml(
                        threat.description
                    )}
                </div>


                <div class="meta">

                    ${escapeHtml(
                        threat.vendor
                    )}

                    ·

                    ${escapeHtml(
                        threat.product
                    )}

                    ·

                    ${escapeHtml(
                        threat.category
                    )}

                </div>

            </div>

        `
        ).join("");

}


/* ============================================================
   OPEN THREAT
   ============================================================ */

async function openThreat(cve) {

    try {

        const response =
            await fetch(
                "/api/threat/" +
                encodeURIComponent(cve)
            );

        const threat =
            await response.json();


        document.getElementById(
            "modalContent"
        ).innerHTML = `

            <h2>
                ${escapeHtml(
                    threat.cve
                )}
            </h2>

            <div class="detail">

                <div class="detail-label">
                    Vulnerability
                </div>

                ${escapeHtml(
                    threat.name
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Vendor
                </div>

                ${escapeHtml(
                    threat.vendor
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Product
                </div>

                ${escapeHtml(
                    threat.product
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Severity
                </div>

                ${escapeHtml(
                    threat.severity
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Category
                </div>

                ${escapeHtml(
                    threat.category
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Ransomware Campaign Use
                </div>

                ${escapeHtml(
                    threat.ransomware
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Description
                </div>

                ${escapeHtml(
                    threat.description
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Required Action
                </div>

                ${escapeHtml(
                    threat.action
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Date Added
                </div>

                ${escapeHtml(
                    threat.dateAdded
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Due Date
                </div>

                ${escapeHtml(
                    threat.dueDate
                )}

            </div>


            <div class="detail">

                <div class="detail-label">
                    Source
                </div>

                <a
                    href="${threat.sourceUrl}"
                    target="_blank"
                >
                    CISA KEV
                </a>

            </div>
        `;


        document.getElementById(
            "modal"
        ).style.display =
            "flex";

    }

    catch(error) {

        console.error(error);

    }

}


/* ============================================================
   CLOSE MODAL
   ============================================================ */

function hideModal() {

    document.getElementById(
        "modal"
    ).style.display =
        "none";

}


function closeModal(event) {

    if (
        event.target.id ===
        "modal"
    ) {

        hideModal();

    }

}


/* ============================================================
   CISA SEARCH
   ============================================================ */

async function searchCISA() {

    const query =
        document.getElementById(
            "cisaSearch"
        ).value.trim();


    if (!query) {

        return;

    }


    const response =
        await fetch(
            "/api/search?q=" +
            encodeURIComponent(query) +
            "&mode=cisa"
        );


    const results =
        await response.json();


    renderThreats(
        results,
        "cisaResults"
    );

}


/* ============================================================
   GLOBAL CYBER SEARCH
   ============================================================ */

async function searchGlobal() {

    const query =
        document.getElementById(
            "globalSearch"
        ).value.trim();


    if (!query) {

        return;

    }


    const container =
        document.getElementById(
            "globalResults"
        );


    container.innerHTML =
        '<div class="empty">' +
        'Searching public cyber intelligence...' +
        '</div>';


    const response =
        await fetch(
            "/api/search?q=" +
            encodeURIComponent(query) +
            "&mode=global"
        );


    const results =
        await response.json();


    renderNews(
        results,
        "globalResults"
    );

}


/* ============================================================
   LOCATION SEARCH
   ============================================================ */

async function searchLocation() {

    const location =
        document.getElementById(
            "locationSearch"
        ).value.trim();


    if (!location) {

        return;

    }


    const info =
        document.getElementById(
            "locationInfo"
        );


    const resultsBox =
        document.getElementById(
            "locationResults"
        );


    info.innerHTML = `

        <div class="detail">

            Searching public cyber threat
            reports related to:

            <strong>
                ${escapeHtml(location)}
            </strong>

        </div>

    `;


    resultsBox.innerHTML =
        '<div class="empty">' +
        'Searching ransomware, phishing, malware, ' +
        'breaches, cyberattacks and other cyber threats...' +
        '</div>';


    try {

        const response =
            await fetch(
                "/api/search?q=" +
                encodeURIComponent(location) +
                "&mode=location"
            );


        const results =
            await response.json();


        renderNews(
            results,
            "locationResults"
        );


        info.innerHTML = `

            <div class="detail">

                <strong>
                    ${results.length}
                </strong>

                cyber threat reports found
                for

                <strong>
                    ${escapeHtml(location)}
                </strong>

            </div>

        `;

    }

    catch(error) {

        resultsBox.innerHTML =
            '<div class="empty">' +
            'Unable to retrieve threat intelligence.' +
            '</div>';

        console.error(error);

    }

}


/* ============================================================
   RENDER NEWS
   ============================================================ */

function renderNews(
    articles,
    containerId
) {

    const container =
        document.getElementById(
            containerId
        );


    if (!articles.length) {

        container.innerHTML = `

            <div class="empty">

                No relevant cyber threat
                reports found.

            </div>

        `;

        return;

    }


    container.innerHTML =
        articles.map(
            article => `

            <div class="news-card">

                <div
                    style="
                    display:flex;
                    justify-content:space-between;
                    gap:10px;
                    "
                >

                    <span>

                        <span
                            class="badge
                            ${String(
                                article.severity
                            ).toLowerCase()}"
                        >

                            ${escapeHtml(
                                article.severity
                            )}

                        </span>

                    </span>


                    <span class="meta">

                        ${escapeHtml(
                            article.category
                        )}

                    </span>

                </div>


                <br>


                <a
                    href="${article.link}"
                    target="_blank"
                >

                    ${escapeHtml(
                        article.title
                    )}

                </a>


                <div class="news-meta">

                    ${escapeHtml(
                        article.source
                    )}

                    ·

                    ${escapeHtml(
                        article.published
                    )}

                </div>


                <div class="threat-description">

                    ${stripHtml(
                        article.description
                    )}

                </div>

            </div>

        `
        ).join("");

}


/* ============================================================
   ANALYTICS
   ============================================================ */

function renderAnalytics() {

    if (!allThreats.length) {

        return;

    }


    const severity = {

        Critical:
            allThreats.filter(
                t =>
                    t.severity ===
                    "Critical"
            ).length,

        High:
            allThreats.filter(
                t =>
                    t.severity ===
                    "High"
            ).length,

        Medium:
            allThreats.filter(
                t =>
                    t.severity ===
                    "Medium"
            ).length
    };


    const categories = {};


    allThreats.forEach(
        threat => {

            categories[
                threat.category
            ] =
                (
                    categories[
                        threat.category
                    ] || 0
                ) + 1;

        }
    );


    renderChart(
        severity,
        "severityChart"
    );


    renderChart(
        categories,
        "categoryChart"
    );

}


/* ============================================================
   CHART
   ============================================================ */

function renderChart(
    data,
    containerId
) {

    const container =
        document.getElementById(
            containerId
        );


    const values =
        Object.values(data);


    const max =
        Math.max(
            ...values,
            1
        );


    container.innerHTML =
        Object.entries(data)
            .map(
                ([label, value]) => `

                <div class="chart-row">

                    <div class="chart-label">

                        <span>
                            ${escapeHtml(label)}
                        </span>

                        <span>
                            ${value}
                        </span>

                    </div>

                    <div class="bar">

                        <div
                            class="bar-fill"
                            style="
                            width:${(
                                value /
                                max *
                                100
                            )}%
                            "
                        ></div>

                    </div>

                </div>

            `
            ).join("");

}


/* ============================================================
   SECURITY HELPERS
   ============================================================ */

function escapeHtml(value) {

    return String(
        value ?? ""
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /'/g,
        "&#039;"
    );

}


function stripHtml(value) {

    const div =
        document.createElement(
            "div"
        );

    div.innerHTML =
        value || "";

    return div.textContent ||
        div.innerText ||
        "";

}


/* ============================================================
   START
   ============================================================ */

loadDashboard();

</script>

</body>

</html>
'''


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )