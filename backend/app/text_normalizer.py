# app/text_normalizer.py
"""
Text normalization and de-obfuscation utilities.
Handles homoglyphs, invisible characters, and common obfuscation techniques.
"""

import unicodedata
import re


class TextNormalizer:
    """Sanitize and normalize text before rule matching."""

    # Common homoglyph mappings (Cyrillic/Greek → Latin)
    HOMOGLYPH_MAP = str.maketrans({
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  # Cyrillic
        'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
        'α': 'a', 'ο': 'o', 'е': 'e',  # Greek
    })

    # Common leet-speak substitutions
    LEET_SPEAK_MAP = str.maketrans({
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', '$': 's',
    })

    @staticmethod
    def normalize(text: str) -> str:
        """
        Normalize text by removing obfuscation and converting to standard form.

        Steps:
        1. Remove zero-width characters
        2. Convert homoglyphs to ASCII equivalents
        3. Convert leet-speak to normal characters
        4. Normalize unicode (NFC form)
        5. Convert to lowercase
        6. Remove excessive whitespace
        """
        if not text:
            return ""

        # Step 1: Remove zero-width and invisible characters
        text = re.sub(r'[\u200B-\u200D\uFEFF]', '', text)  # Zero-width spaces
        text = re.sub(r'[\u00AD]', '', text)  # Soft hyphens

        # Step 2: Convert homoglyphs
        text = text.translate(TextNormalizer.HOMOGLYPH_MAP)

        # Step 3: Convert leet-speak (optional, can be aggressive)
        text = text.translate(TextNormalizer.LEET_SPEAK_MAP)

        # Step 4: Unicode normalization
        text = unicodedata.normalize('NFC', text)

        # Step 5: Lowercase
        text = text.lower()

        # Step 6: Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        return text