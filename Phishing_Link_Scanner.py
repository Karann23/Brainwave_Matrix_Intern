import re
import tldextract
from urllib.parse import urlparse
from Levenshtein import ratio

trusted_domains = ["google.com", "facebook.com", "cybersec.com"]

# Heuristic Checks

def is_ip_domain(url):
    hostname = urlparse(url).hostname or ""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

# Check TLD

def has_sus_tld(url):
    return url.lower().endswith((".exe", "gq", ".tk", ".cf", ".config", ".ml", ".boot"))

# Check special chars

def contains_sus_chars(url):
    return any(c in url for c in ["@", " ", "%", "&", "!"])

# Check length of url

def is_long_url(url, threshold=200):
    return len(url) > threshold

# Check punycode

def contains_punnycode(url):
    return "xn--" in url.lower()

# Check the severity

def heuristic_score(url):
    score = sum([
        is_ip_domain(url),
        has_sus_tld(url),
        contains_sus_chars(url),
        is_long_url(url),
        contains_punnycode(url)
    ])
    return score


# check typo-squatting

def typo_check(url, trusted_domains, threshold=0.8):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    for trusted in trusted_domains:
        if domain == trusted:
            continue 
        if ratio(domain, trusted) >= threshold:
            return True
    return False

# Main Scanner

def scan_url(url):
    if typo_check(url, trusted_domains):
        return True, "Typo-squatting match!!"
    
    if contains_punnycode(url):
        return True, "May be sus!!"
    
    score = heuristic_score(url)
    if score >= 3:
        return True, "Heuristic Score: {score}"
    
    return False, "Looks Safe.."


if __name__ == "__main__":
    test_urls = [
        "google.com",
        "faceboook.com",
        "exam-portal.com",
        "google.com-login.info",
        "xn--google-yva.com",
        "192.168.0.1/phish"
    ]

    for url in test_urls:
        result, reason = scan = scan_url(url)
        print(f"[{ "PHISING" if result else "SAFE" }] {url} -> {reason}")