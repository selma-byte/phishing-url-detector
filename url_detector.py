
import re
import ipaddress
from urllib.parse import urlparse


def analyze_url(url):
    score = 0
    warnings = []

    url = url.strip()

    if not url:
        print("Please enter a URL.")
        return

    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            print("Invalid URL.")
            return

        # Check URL length
        if len(url) > 75:
            score += 1
            warnings.append("Unusually long URL")

        # Check HTTPS
        if parsed.scheme != "https":
            score += 1
            warnings.append("Not using HTTPS")

        # Check for IP address instead of domain
        try:
            ipaddress.ip_address(domain)
            score += 3
            warnings.append("Uses an IP address instead of a domain")
        except ValueError:
            pass

        # Check for suspicious @ symbol
        if "@" in parsed.netloc:
            score += 2
            warnings.append("Contains an @ symbol")

        # Check subdomains
        if len(domain.split(".")) > 3:
            score += 1
            warnings.append("Contains multiple subdomains")

        # Check suspicious keywords
        keywords = [
            "login", "verify", "account",
            "password", "banking", "secure"
        ]

        if any(word in url.lower() for word in keywords):
            score += 1
            warnings.append("Contains suspicious keywords")

        # Determine risk level
        if score >= 5:
            risk = "HIGH"
        elif score >= 3:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print("\n========== URL ANALYSIS ==========")
        print("URL:", url)
        print("Risk score:", score)
        print("Risk level:", risk)

        print("\nFindings:")

        if warnings:
            for warning in warnings:
                print("[-]", warning)
        else:
            print("[+] No obvious suspicious indicators found.")

        print("==================================")

    except ValueError:
        print("Invalid URL format.")


if __name__ == "__main__":
    print("==================================")
    print("       PHISHING URL DETECTOR")
    print("==================================")

    user_url = input("\nEnter a URL to analyze: ")

    analyze_url(user_url)
