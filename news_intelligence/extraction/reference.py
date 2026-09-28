"""
news_intelligence.extraction.reference — curated public naming reference data.

Small, hand-curated dictionaries of *publicly documented* names used to raise
extraction precision: threat-actor alias clusters (as published by vendors and
MITRE ATT&CK), well-known malware family names/aliases, country names + demonyms,
major security-relevant organizations and vendors, and cloud providers.

These are naming conventions, not attribution. An alias cluster records that
several public names have been *reported* for what may be the same activity; it
never asserts they are the same identity — that judgement stays with the
correlation layer's evidence-gated alias links and, ultimately, the reader.

All names here are public knowledge (vendor blogs, MITRE ATT&CK, national CERTs).
The lists are intentionally conservative and extensible via
``NI_EXTRA_*`` environment overrides handled by the extractors.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple


# --- threat actor alias clusters ------------------------------------------- #
# Each tuple: (canonical/most-common name, [reported aliases]). Public, as
# documented by MITRE ATT&CK Groups and vendor naming.
ACTOR_ALIAS_CLUSTERS: List[Tuple[str, List[str]]] = [
    ("APT29", ["Cozy Bear", "Midnight Blizzard", "Nobelium", "UNC2452",
               "The Dukes", "Yttrium", "Cloaked Ursa"]),
    ("APT28", ["Fancy Bear", "Sofacy", "Sednit", "Strontium", "Forest Blizzard",
               "Pawn Storm"]),
    ("Lazarus Group", ["Hidden Cobra", "Zinc", "Diamond Sleet", "Labyrinth Chollima",
                       "APT38", "Guardians of Peace"]),
    ("APT41", ["Winnti", "Barium", "Wicked Panda", "Brass Typhoon", "Double Dragon"]),
    ("Volt Typhoon", ["Vanguard Panda", "Bronze Silhouette", "Insidious Taurus"]),
    ("Sandworm", ["Voodoo Bear", "Seashell Blizzard", "Iridium", "APT44",
                  "Telebots"]),
    ("APT10", ["Stone Panda", "MenuPass", "Cicada", "Potassium"]),
    ("Mustang Panda", ["Bronze President", "RedDelta", "Earth Preta",
                       "Twill Typhoon"]),
    ("Kimsuky", ["Velvet Chollima", "Emerald Sleet", "Thallium", "Black Banshee"]),
    ("FIN7", ["Carbanak", "Carbon Spider", "Sangria Tempest"]),
    ("Scattered Spider", ["Octo Tempest", "UNC3944", "Muddled Libra",
                          "Roasted 0ktapus"]),
    ("Lapsus$", ["Strawberry Tempest", "DEV-0537"]),
    ("Turla", ["Snake", "Venomous Bear", "Waterbug", "Secret Blizzard"]),
    ("Wizard Spider", ["UNC1878", "Trickbot Gang", "Grim Spider"]),
    ("Charming Kitten", ["APT35", "Phosphorus", "Mint Sandstorm", "TA453"]),
    ("MuddyWater", ["Static Kitten", "Mercury", "Mango Sandstorm", "Seedworm"]),
    ("OilRig", ["APT34", "Helix Kitten", "Hazel Sandstorm", "Cobalt Gypsy"]),
    ("BlackCat", ["ALPHV", "Noberus"]),
    ("LockBit", ["Bitwise Spider"]),
    ("Cl0p", ["Clop", "TA505", "Graceful Spider"]),
]


def build_actor_index() -> Dict[str, str]:
    """Map every reported name (lowercased) -> canonical name."""
    idx: Dict[str, str] = {}
    for canonical, aliases in ACTOR_ALIAS_CLUSTERS:
        idx[canonical.lower()] = canonical
        for a in aliases:
            idx[a.lower()] = canonical
    return idx


def actor_aliases_for(canonical: str) -> List[str]:
    for c, aliases in ACTOR_ALIAS_CLUSTERS:
        if c.lower() == canonical.lower():
            return list(aliases)
    return []


# --- malware family names + aliases ---------------------------------------- #
MALWARE_ALIAS_CLUSTERS: List[Tuple[str, List[str], str]] = [
    # (canonical, aliases, category)
    ("Cobalt Strike", ["CobaltStrike", "Beacon"], "post-exploitation"),
    ("Emotet", ["Geodo", "Heodo"], "loader"),
    ("TrickBot", ["Trickbot", "TrickLoader"], "banking-trojan"),
    ("QakBot", ["Qbot", "Quakbot", "Pinkslipbot"], "banking-trojan"),
    ("IcedID", ["BokBot"], "loader"),
    ("BumbleBee", ["Bumblebee"], "loader"),
    ("Mimikatz", [], "credential-theft"),
    ("PlugX", ["Korplug", "SOGU"], "rat"),
    ("ShadowPad", [], "backdoor"),
    ("Ryuk", [], "ransomware"),
    ("Conti", [], "ransomware"),
    ("LockBit", ["LockBit 3.0", "LockBit Black"], "ransomware"),
    ("BlackCat", ["ALPHV", "Noberus"], "ransomware"),
    ("Cl0p", ["Clop"], "ransomware"),
    ("BlackBasta", ["Black Basta"], "ransomware"),
    ("Akira", [], "ransomware"),
    ("Play", ["PlayCrypt"], "ransomware"),
    ("Royal", [], "ransomware"),
    ("Snake", ["Turla", "Uroburos"], "backdoor"),
    ("Raspberry Robin", ["QNAP worm"], "worm"),
    ("Gootloader", ["GootLoader"], "loader"),
    ("SocGholish", ["FakeUpdates"], "loader"),
    ("Redline", ["RedLine Stealer"], "stealer"),
    ("Lumma", ["LummaC2", "Lumma Stealer"], "stealer"),
    ("Vidar", [], "stealer"),
    ("Raccoon", ["Raccoon Stealer"], "stealer"),
    ("AsyncRAT", ["Async RAT"], "rat"),
    ("Remcos", ["Remcos RAT"], "rat"),
    ("njRAT", ["Bladabindi"], "rat"),
    ("Agent Tesla", ["AgentTesla"], "stealer"),
    ("FormBook", ["Formbook", "XLoader"], "stealer"),
]


def build_malware_index() -> Dict[str, Tuple[str, str]]:
    """Map reported name (lowercased) -> (canonical, category)."""
    idx: Dict[str, Tuple[str, str]] = {}
    for canonical, aliases, category in MALWARE_ALIAS_CLUSTERS:
        idx[canonical.lower()] = (canonical, category)
        for a in aliases:
            idx[a.lower()] = (canonical, category)
    return idx


def malware_aliases_for(canonical: str) -> Tuple[List[str], str]:
    for c, aliases, category in MALWARE_ALIAS_CLUSTERS:
        if c.lower() == canonical.lower():
            return list(aliases), category
    return [], ""


# --- countries + demonyms -------------------------------------------------- #
COUNTRIES: Dict[str, List[str]] = {
    "United States": ["USA", "U.S.", "US", "America", "American"],
    "United Kingdom": ["UK", "Britain", "British", "England"],
    "China": ["Chinese", "PRC", "People's Republic of China"],
    "Russia": ["Russian", "Russian Federation"],
    "North Korea": ["DPRK", "North Korean"],
    "South Korea": ["Republic of Korea", "South Korean"],
    "Iran": ["Iranian", "Islamic Republic of Iran"],
    "Israel": ["Israeli"],
    "Ukraine": ["Ukrainian"],
    "Germany": ["German"],
    "France": ["French"],
    "India": ["Indian"],
    "Japan": ["Japanese"],
    "Australia": ["Australian"],
    "Canada": ["Canadian"],
    "Brazil": ["Brazilian"],
    "Taiwan": ["Taiwanese"],
    "Vietnam": ["Vietnamese"],
    "Pakistan": ["Pakistani"],
    "Saudi Arabia": ["Saudi"],
    "Turkey": ["Turkish", "Türkiye"],
    "Netherlands": ["Dutch"],
    "Italy": ["Italian"],
    "Spain": ["Spanish"],
    "Poland": ["Polish"],
    "Singapore": ["Singaporean"],
}


def build_country_index() -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for canonical, demonyms in COUNTRIES.items():
        idx[canonical.lower()] = canonical
        for d in demonyms:
            idx[d.lower()] = canonical
    return idx


# --- organizations / vendors / agencies ------------------------------------ #
ORGANIZATIONS: Set[str] = {
    "Microsoft", "Google", "Apple", "Amazon", "AWS", "Cloudflare", "Cisco",
    "Fortinet", "Palo Alto Networks", "CrowdStrike", "Mandiant", "FireEye",
    "Kaspersky", "ESET", "Symantec", "Trend Micro", "Sophos", "SentinelOne",
    "Check Point", "Recorded Future", "Proofpoint", "Rapid7", "Tenable",
    "Qualys", "Ivanti", "Citrix", "VMware", "Oracle", "SolarWinds", "MOVEit",
    "Okta", "Cloudflare", "GitHub", "GitLab", "Atlassian", "Zoom", "Slack",
    "CISA", "FBI", "NSA", "NCSC", "ENISA", "Europol", "Interpol", "MITRE",
    "NIST", "US-CERT", "CERT-EU", "ANSSI", "BSI", "ACSC",
}

GOVERNMENT_AGENCIES: Set[str] = {
    "CISA", "FBI", "NSA", "NCSC", "ENISA", "Europol", "Interpol", "US-CERT",
    "CERT-EU", "ANSSI", "BSI", "ACSC", "CCCS", "JPCERT", "KISA",
}

CLOUD_PROVIDERS: Set[str] = {
    "AWS", "Amazon Web Services", "Azure", "Microsoft Azure",
    "Google Cloud", "GCP", "Cloudflare", "DigitalOcean", "Oracle Cloud",
    "Alibaba Cloud", "Linode", "Vultr", "OVH", "Hetzner",
}


__all__ = [
    "ACTOR_ALIAS_CLUSTERS", "build_actor_index", "actor_aliases_for",
    "MALWARE_ALIAS_CLUSTERS", "build_malware_index", "malware_aliases_for",
    "COUNTRIES", "build_country_index",
    "ORGANIZATIONS", "GOVERNMENT_AGENCIES", "CLOUD_PROVIDERS",
]
