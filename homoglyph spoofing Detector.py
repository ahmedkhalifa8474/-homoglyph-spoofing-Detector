import re
import unicodedata

# Define allowed ASCII characters for a valid domain
VALID_ASCII = "abcdefghijklmnopqrstuvwxyz0123456789.-"

# List of common homoglyphs mapped to their ASCII equivalent
HOMOGLYPH_MAP = {
    "ɑ": "a", "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "ѕ": "s", "υ": "u",
    "О": "O", "0": "O", "Ⅰ": "I", "l": "I", "ⅼ": "l",
    "Ꞓ": "C", "Ϲ": "C", "Ⅽ": "C",
    # Add more homoglyph mappings as needed
}

def is_homoglyph_spoof(domain):
    """
    Detect if a domain contains homoglyph spoofing.
    Args:
        domain (str): The domain to check.
    Returns:
        bool: True if spoofing is detected, False otherwise.
    """
    for char in domain:
        # Check if character is not ASCII or is in the homoglyph map
        if char.lower() not in VALID_ASCII and char not in HOMOGLYPH_MAP:
            char_name = unicodedata.name(char, "")
            print(f"Suspicious character detected: '{char}' ({char_name})")
            return True
    
    # Check for characters explicitly mapped as homoglyphs
    for char in domain:
        if char in HOMOGLYPH_MAP:
            print(f"Potential homoglyph detected: '{char}' replaced by '{HOMOGLYPH_MAP[char]}'")
            return True

    return False

def validate_input(input_text):
    """
    Validate whether the input is an email address, a URL, or a plain domain.
    Args:
        input_text (str): The input text to validate.
    Returns:
        str: The domain part for further processing.
    """
    # Check if the input is an email address
    if "@" in input_text:
        email_pattern = r"^[^@]+@([^\s@]+)$"  # Allow non-ASCII characters in the domain part
        match = re.match(email_pattern, input_text)
        if match:
            return match.group(1)  # Return the domain part
        else:
            raise ValueError("Invalid email address format.")
    
    # Check if the input is a URL
    url_pattern = r"https?://([^\s/]+)"
    match = re.match(url_pattern, input_text)
    if match:
        return match.group(1)  # Return the domain part

    # Assume input is a plain domain if it passes a basic domain format check
    domain_pattern = r"^[^\s@]+\.[a-zA-Z]{2,}$"
    match = re.match(domain_pattern, input_text)
    if match:
        return input_text  # Return the plain domain

    raise ValueError("Invalid input format. Please provide a valid email, URL, or domain.")

if __name__ == "__main__":
    print("Homoglyph Spoofing Detection Tool")
    user_input = input("Enter a URL, email address, or domain to check: ").strip()

    try:
        domain = validate_input(user_input)
        if is_homoglyph_spoof(domain):
            print("🚩 This domain contains homoglyph spoofing and may be fake!")
        else:
            print("✅ This domain appears to be safe.")
    except ValueError as e:
        print(f"Error: {e}")
