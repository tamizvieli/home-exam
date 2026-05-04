"""
Core rules-based scoring engine for email maliciousness detection.
Implements deterministic weighted heuristics with zero external API calls.
Philosophy: Privacy-first, static analysis only.
"""

import re
from typing import List, Tuple, Dict
from bs4 import BeautifulSoup
from app.config import (
    WEIGHTS,
    BAD_TLDS,
    FREE_PROVIDERS,
    URL_SHORTENERS,
    SOCIAL_ENGINEERING_KEYWORDS,
    URGENCY_KEYWORDS,
    URGENCY_PATTERNS,
    THRESHOLDS,
    VERDICTS,
    EXPLANATIONS,
)
from app.text_normalizer import TextNormalizer


class ScoringEngine:
    def __init__(self) -> None:
        self.score: int = 0
        self.explanations: List[str] = []
        self.urgency_detected: bool = False
        self.normalizer = TextNormalizer()

    def analyze(
            self,
            sender: str,
            subject: str,
            body_html: str,
            body_text: str,
            attachment_extensions: List[str],
            headers: Dict[str, str]
    ) -> Tuple[int, str, List[str]]:
        """
        Main analysis entry point. Runs all rule checks and returns final verdict.

        Args:
            sender: Email sender address
            subject: Email subject line
            body_html: Email body in HTML format
            body_text: Email body in plain text
            attachment_extensions: List of file extensions
            headers: Email headers dict

        Returns:
            Tuple of (score, risk_level, explanations)
        """
        self.score = 0
        self.explanations = []
        self.urgency_detected = False

        # Rule 1: Sender Authentication
        self._check_sender_authentication(headers)

        # Rule 2: Domain Spoofing
        self._check_domain_spoofing(sender)

        # Rule 3: Link Manipulation
        self._check_link_manipulation(body_html)

        # Rule 4: Social Engineering
        self._check_social_engineering(body_text, subject)

        # Rule 5: Urgency Language
        self._check_urgency_language(body_text, subject)

        # Rule 6: Attachment + Urgency Combo
        self._check_attachment_with_urgency(attachment_extensions)

        # Cap score at 100 (safety measure)
        self.score = min(self.score, 100)

        # Determine risk level based on score
        risk_level = self._get_risk_level(self.score)

        return self.score, risk_level, self.explanations

    def _check_sender_authentication(self, headers: dict):
        """
        Check if sender authentication (SPF/DKIM) passed.

        Parses Gmail's authentication_results header to determine if the sender's
        domain has valid SPF records and DKIM signatures.

        Args:
            headers (dict): Email headers, expected to contain 'authentication_results'

        Scoring:
            +30 points if SPF fails or DKIM fails/none

        Edge Cases:
            - Missing headers dict: Treat as fail (suspicious)
            - Missing authentication_results: Treat as fail (suspicious)
            - Empty authentication_results: Treat as fail (suspicious)
        """
        auth_results = headers.get("authentication_results", "").lower()

        # Edge case: No authentication header = suspicious
        if not auth_results:
            self.score += WEIGHTS["sender_authentication"]
            self.explanations.append(EXPLANATIONS["sender_auth_fail"])
            return

        # Check for explicit failures
        if "spf=fail" in auth_results or "dkim=fail" in auth_results or "dkim=none" in auth_results:
            self.score += WEIGHTS["sender_authentication"]
            self.explanations.append(EXPLANATIONS["sender_auth_fail"])

    def _check_domain_spoofing(self, sender: str):
        """
        Check for bad TLDs and free email providers.

        Args:
            sender (str): Email sender address

        Scoring:
            +40 points for bad TLD (.tk, .xyz, etc.)
            +20 points for free email provider (gmail.com, yahoo.com, etc.)

        Max points: 60 (bad TLD + free provider)
        """
        sender_lower = sender.lower()

        # Check for bad TLDs
        for tld in BAD_TLDS:
            if sender_lower.endswith(tld):
                self.score += WEIGHTS["domain_spoofing_bad_tld"]
                self.explanations.append(EXPLANATIONS["domain_spoofing"])
                return  # Only trigger once

        # Check for free email providers
        domain = sender_lower.split("@")[-1] if "@" in sender_lower else ""
        if domain in FREE_PROVIDERS:
            self.score += WEIGHTS["domain_spoofing_free_provider"]
            self.explanations.append(EXPLANATIONS["domain_spoofing"])

    def _check_link_manipulation(self, body_html: str):
        """
        Extract links from HTML and check for suspicious patterns.

        Detects:
        1. URL shorteners (bit.ly, tinyurl, etc.)
        2. URL mismatch (display text != actual href)

        Args:
            body_html (str): Email body in HTML format

        Scoring:
            +20 points per suspicious link
            Max: 40 points (category ceiling)
        """
        if not body_html:
            return

        soup = BeautifulSoup(body_html, "html.parser")
        links = soup.find_all("a", href=True)

        link_manipulation_score = 0  # Track category-specific score
        suspicious_links_found = False

        for link in links:
            href = link.get("href", "").lower()
            display_text = link.get_text(strip=True).lower()

            # Check for URL shorteners
            if any(shortener in href for shortener in URL_SHORTENERS):
                link_manipulation_score = min(
                    link_manipulation_score + WEIGHTS["link_manipulation_per_link"],
                    WEIGHTS["link_manipulation_max"]
                )
                suspicious_links_found = True
                continue

            # Check for URL mismatch (basic heuristic: display text looks like URL but differs)
            if display_text and ("http" in display_text or "www" in display_text):
                # Extract domain from display text (simple extraction)
                display_domain = self._extract_domain(display_text)
                href_domain = self._extract_domain(href)

                if display_domain and href_domain and display_domain != href_domain:
                    link_manipulation_score = min(
                        link_manipulation_score + WEIGHTS["link_manipulation_per_link"],
                        WEIGHTS["link_manipulation_max"]
                    )
                    suspicious_links_found = True

        if suspicious_links_found:
            self.score += link_manipulation_score
            self.explanations.append(EXPLANATIONS["link_manipulation"])

    def _extract_domain(self, url: str) -> str:
        """
        Simple domain extraction from URL string.

        Args:
            url (str): URL string (may include protocol, path, query params)

        Returns:
            str: Extracted domain or empty string if not found
        """
        # Remove protocol
        url = re.sub(r"https?://", "", url)
        url = re.sub(r"www\.", "", url)
        # Extract domain (first part before /)
        domain = url.split("/")[0].split("?")[0]
        return domain

    def _check_social_engineering(self, body_text: str, subject: str):
        """
        Check for explicit requests for sensitive information.

        Uses text normalization to detect obfuscated keywords like:
        - "p4ssw0rd" → "password"
        - Cyrillic 'а' → Latin 'a'
        - Invisible characters removed

        Args:
            body_text (str): Email body in plain text
            subject (str): Email subject line

        Scoring:
            +40 points if any social engineering keyword detected

        Max points: 40 (triggers once)
        """
        combined_text = body_text + " " + subject

        # Normalize text to handle obfuscation (homoglyphs, leet-speak, etc.)
        normalized_text = self.normalizer.normalize(combined_text)

        for keyword in SOCIAL_ENGINEERING_KEYWORDS:
            if keyword in normalized_text:
                self.score += WEIGHTS["social_engineering"]
                self.explanations.append(EXPLANATIONS["social_engineering"])
                return  # Only trigger once

    def _check_urgency_language(self, body_text: str, subject: str):
        """
        Check for urgency-inducing language using dual detection:
        1. Normalized keyword matching (handles obfuscation like "URG3NT")
        2. Regex pattern matching (flexible phrase detection)

        Args:
            body_text (str): Email body in plain text
            subject (str): Email subject line

        Scoring:
            +15 points if urgency detected

        Max points: 15 (triggers once)
        """
        combined_text = body_text + " " + subject

        # Normalize text to handle obfuscation (homoglyphs, leet-speak, invisible chars)
        normalized_text = self.normalizer.normalize(combined_text)

        # Check keywords (after normalization)
        for keyword in URGENCY_KEYWORDS:
            if keyword in normalized_text:
                self.score += WEIGHTS["urgency_language"]
                self.explanations.append(EXPLANATIONS["urgency_language"])
                self.urgency_detected = True  # Set flag for combo rule
                return  # Only trigger once

        # Check regex patterns (on normalized text)
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, normalized_text, re.IGNORECASE):
                self.score += WEIGHTS["urgency_language"]
                self.explanations.append(EXPLANATIONS["urgency_language"])
                self.urgency_detected = True  # Set flag for combo rule
                return  # Only trigger once

    def _check_attachment_with_urgency(self, attachment_extensions: List[str]):
        """
        Check for combination of attachments + urgency language.

        This pattern is highly suspicious as attackers often combine:
        - Malicious attachment (.exe, .zip, etc.)
        - Urgent language to pressure victims into opening it

        Args:
            attachment_extensions (List[str]): List of file extensions

        Scoring:
            +10 points (bonus) if both conditions met

        Max points: 10
        """
        if attachment_extensions and self.urgency_detected:
            self.score += WEIGHTS["attachment_with_urgency"]
            self.explanations.append(EXPLANATIONS["attachment_with_urgency"])

    def _get_risk_level(self, score: int) -> str:
        """
        Map score to risk level based on thresholds.

        Args:
            score (int): Total maliciousness score (0-100)

        Returns:
            str: Risk level ("safe", "suspicious", or "dangerous")
        """
        if THRESHOLDS["safe"][0] <= score <= THRESHOLDS["safe"][1]:
            return "safe"
        elif THRESHOLDS["suspicious"][0] <= score <= THRESHOLDS["suspicious"][1]:
            return "suspicious"
        else:
            return "dangerous"

    @staticmethod
    def get_verdict(risk_level: str) -> str:
        """
        Get the Hebrew verdict message for a given risk level.

        Args:
            risk_level (str): Risk level ("safe", "suspicious", or "dangerous")

        Returns:
            str: Hebrew verdict message
        """
        return VERDICTS.get(risk_level, "לא ידוע")