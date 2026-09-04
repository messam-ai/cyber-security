# ============================================================
#          CYBER SECURITY PROJECT 3
#          PHISHING AWARENESS ANALYSIS
#          DecodeLabs - Batch 2026
# ============================================================

import re
from urllib.parse import urlparse


# ============================================================
#                 PHISHING ANALYZER CLASS
# ============================================================

class PhishingAnalyzer:

    def __init__(self):
        # Suspicious words commonly found in phishing messages
        self.suspicious_keywords = {
            "urgent": 2,
            "immediately": 2,
            "verify": 2,
            "verification": 2,
            "account": 1,
            "suspended": 3,
            "blocked": 3,
            "password": 2,
            "login": 2,
            "confirm": 2,
            "click": 2,
            "winner": 3,
            "won": 3,
            "prize": 3,
            "reward": 2,
            "free": 2,
            "offer": 1,
            "gift": 2,
            "bank": 1,
            "payment": 2,
            "refund": 2,
            "security alert": 3,
            "limited time": 2,
            "act now": 3,
            "dear customer": 2,
            "dear user": 2
        }

        # Common URL shorteners
        self.shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "cutt.ly",
            "ow.ly",
            "shorturl.at"
        ]

        # Suspicious URL patterns
        self.suspicious_extensions = [
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq"
        ]


    # ========================================================
    #                 KEYWORD ANALYSIS
    # ========================================================

    def detect_keywords(self, message):

        found_keywords = []
        score = 0

        message_lower = message.lower()

        for keyword, points in self.suspicious_keywords.items():

            if keyword in message_lower:

                found_keywords.append(keyword)
                score += points

        return found_keywords, score


    # ========================================================
    #                    URL EXTRACTION
    # ========================================================

    def extract_urls(self, message):

        url_pattern = r'https?://[^\s]+|www\.[^\s]+'

        urls = re.findall(url_pattern, message)

        return urls


    # ========================================================
    #                  URL ANALYSIS
    # ========================================================

    def analyze_urls(self, urls):

        red_flags = []
        score = 0

        for url in urls:

            clean_url = url.rstrip(".,!?;:)")

            # Add protocol if missing
            if clean_url.startswith("www."):
                parsed_url = urlparse("http://" + clean_url)
            else:
                parsed_url = urlparse(clean_url)

            domain = parsed_url.netloc.lower()

            # ------------------------------------------------
            # Check HTTPS
            # ------------------------------------------------

            if clean_url.startswith("http://"):

                red_flags.append(
                    f"URL does not use HTTPS: {clean_url}"
                )

                score += 2


            # ------------------------------------------------
            # Check URL shorteners
            # ------------------------------------------------

            if domain in self.shorteners:

                red_flags.append(
                    f"URL shortener detected: {clean_url}"
                )

                score += 3


            # ------------------------------------------------
            # Check IP address in URL
            # ------------------------------------------------

            ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'

            if re.match(ip_pattern, domain):

                red_flags.append(
                    f"URL uses an IP address instead of a domain: {clean_url}"
                )

                score += 4


            # ------------------------------------------------
            # Check suspicious domain extensions
            # ------------------------------------------------

            for extension in self.suspicious_extensions:

                if domain.endswith(extension):

                    red_flags.append(
                        f"Suspicious domain extension detected: {clean_url}"
                    )

                    score += 3

                    break


            # ------------------------------------------------
            # Check @ symbol
            # ------------------------------------------------

            if "@" in clean_url:

                red_flags.append(
                    f"URL contains '@' symbol: {clean_url}"
                )

                score += 4


            # ------------------------------------------------
            # Check excessive hyphens
            # ------------------------------------------------

            if domain.count("-") >= 2:

                red_flags.append(
                    f"Domain contains multiple hyphens: {clean_url}"
                )

                score += 2


            # ------------------------------------------------
            # Check suspicious words in URL
            # ------------------------------------------------

            suspicious_url_words = [
                "login",
                "verify",
                "account",
                "secure",
                "update",
                "password",
                "confirm",
                "bank",
                "wallet"
            ]

            for word in suspicious_url_words:

                if word in clean_url.lower():

                    red_flags.append(
                        f"Suspicious keyword '{word}' found in URL: {clean_url}"
                    )

                    score += 2

                    break

        return red_flags, score


    # ========================================================
    #                MESSAGE RED FLAG ANALYSIS
    # ========================================================

    def analyze_message(self, message):

        red_flags = []
        score = 0

        message_lower = message.lower()


        # ----------------------------------------------------
        # Urgency detection
        # ----------------------------------------------------

        urgency_words = [
            "urgent",
            "immediately",
            "act now",
            "as soon as possible",
            "within 24 hours",
            "limited time"
        ]

        for word in urgency_words:

            if word in message_lower:

                red_flags.append(
                    "Urgency or pressure to act quickly"
                )

                score += 3

                break


        # ----------------------------------------------------
        # Personal information request
        # ----------------------------------------------------

        sensitive_requests = [
            "password",
            "credit card",
            "card number",
            "cvv",
            "otp",
            "pin",
            "bank details",
            "account details",
            "social security"
        ]

        for item in sensitive_requests:

            if item in message_lower:

                red_flags.append(
                    f"Message requests sensitive information: {item}"
                )

                score += 4

                break


        # ----------------------------------------------------
        # Threat detection
        # ----------------------------------------------------

        threats = [
            "account will be closed",
            "account will be suspended",
            "legal action",
            "your account is blocked",
            "your account has been suspended"
        ]

        for threat in threats:

            if threat in message_lower:

                red_flags.append(
                    "Threat or fear-based language detected"
                )

                score += 3

                break


        # ----------------------------------------------------
        # Reward / Prize detection
        # ----------------------------------------------------

        rewards = [
            "you won",
            "winner",
            "prize",
            "reward",
            "free gift",
            "congratulations"
        ]

        for reward in rewards:

            if reward in message_lower:

                red_flags.append(
                    "Unexpected prize, reward, or free offer"
                )

                score += 3

                break


        # ----------------------------------------------------
        # Generic greeting
        # ----------------------------------------------------

        generic_greetings = [
            "dear customer",
            "dear user",
            "dear member",
            "dear account holder"
        ]

        for greeting in generic_greetings:

            if greeting in message_lower:

                red_flags.append(
                    "Generic greeting instead of personalized communication"
                )

                score += 2

                break


        # ----------------------------------------------------
        # Spelling / grammar indicators
        # ----------------------------------------------------

        grammar_indicators = [
            "kindly do the needful",
            "congratulation you",
            "your account have",
            "click here immediately"
        ]

        for phrase in grammar_indicators:

            if phrase in message_lower:

                red_flags.append(
                    "Unusual grammar or wording"
                )

                score += 2

                break


        return red_flags, score


    # ========================================================
    #                 RISK LEVEL
    # ========================================================

    def calculate_risk(self, score):

        if score >= 15:

            return "HIGH RISK - LIKELY PHISHING"

        elif score >= 8:

            return "SUSPICIOUS - POSSIBLE PHISHING"

        else:

            return "LOW RISK - NO STRONG PHISHING INDICATORS"


    # ========================================================
    #              COMPLETE MESSAGE ANALYSIS
    # ========================================================

    def analyze(self, message):

        keyword_flags, keyword_score = self.detect_keywords(message)

        urls = self.extract_urls(message)

        url_flags, url_score = self.analyze_urls(urls)

        message_flags, message_score = self.analyze_message(message)

        all_flags = []

        all_flags.extend(message_flags)
        all_flags.extend(keyword_flags)

        # Convert keyword names into readable red flags
        keyword_red_flags = []

        for keyword in keyword_flags:

            keyword_red_flags.append(
                f"Suspicious keyword detected: '{keyword}'"
            )

        all_flags.extend(keyword_red_flags)
        all_flags.extend(url_flags)

        total_score = (
            keyword_score +
            url_score +
            message_score
        )

        risk = self.calculate_risk(total_score)

        return {
            "score": total_score,
            "risk": risk,
            "keywords": keyword_flags,
            "urls": urls,
            "red_flags": all_flags
        }


# ============================================================
#                  DISPLAY FUNCTIONS
# ============================================================

def print_line():

    print("=" * 65)


def display_result(message, result):

    print("\n")
    print_line()
    print("              PHISHING ANALYSIS REPORT")
    print_line()

    print("\nMessage Analyzed:")
    print("-" * 65)
    print(message)

    print("\nRisk Score:", result["score"])

    print("Risk Level:", result["risk"])


    # --------------------------------------------------------
    # Keywords
    # --------------------------------------------------------

    print("\nSuspicious Keywords:")
    print("-" * 65)

    if result["keywords"]:

        for keyword in result["keywords"]:

            print(f"[!] {keyword}")

    else:

        print("[+] No suspicious keywords detected.")


    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    print("\nLinks / URLs Found:")
    print("-" * 65)

    if result["urls"]:

        for url in result["urls"]:

            print(f"[!] {url}")

    else:

        print("[+] No URL found.")


    # --------------------------------------------------------
    # Red Flags
    # --------------------------------------------------------

    print("\nRed Flags:")
    print("-" * 65)

    if result["red_flags"]:

        unique_flags = list(dict.fromkeys(result["red_flags"]))

        for number, flag in enumerate(unique_flags, start=1):

            print(f"{number}. {flag}")

    else:

        print("[+] No major red flags detected.")


    # --------------------------------------------------------
    # Safety Explanation
    # --------------------------------------------------------

    print("\nWhy is this message unsafe?")
    print("-" * 65)

    if result["score"] >= 15:

        print(
            "This message contains multiple phishing indicators. "
            "It may be attempting to steal credentials, personal "
            "information, or financial information."
        )

        print(
            "\nRecommendation: Do NOT click links, do NOT provide "
            "personal information, and report the message."
        )

    elif result["score"] >= 8:

        print(
            "This message contains several suspicious indicators. "
            "It should be treated carefully and verified through "
            "an official source."
        )

        print(
            "\nRecommendation: Avoid clicking links and verify "
            "the sender independently."
        )

    else:

        print(
            "No strong phishing indicators were detected by this "
            "basic analyzer. However, automated analysis cannot "
            "guarantee that a message is completely safe."
        )

        print(
            "\nRecommendation: Always verify unexpected messages "
            "before clicking links or sharing information."
        )

    print_line()


# ============================================================
#                  SAMPLE MESSAGES
# ============================================================

sample_messages = [

    {
        "name": "Bank Account Alert",
        "message":
        "URGENT! Your bank account has been suspended. "
        "Verify your account immediately by clicking "
        "http://secure-bank-login.com/verify. "
        "Enter your password and OTP to restore access."
    },

    {
        "name": "Prize Scam",
        "message":
        "Congratulations! You are the winner of a FREE gift. "
        "Claim your reward immediately by clicking "
        "https://bit.ly/free-reward. Limited time offer!"
    },

    {
        "name": "Suspicious Login",
        "message":
        "Dear customer, we detected unusual activity on your "
        "account. Please verify your password at "
        "http://192.168.10.20/login immediately."
    },

    {
        "name": "Normal Message",
        "message":
        "Hello Ahmed, your meeting is scheduled for tomorrow "
        "at 10 AM. Please bring your project documents."
    }
]


# ============================================================
#                       MAIN MENU
# ============================================================

def main():

    analyzer = PhishingAnalyzer()

    while True:

        print("\n")

        print_line()

        print("        CYBER SECURITY - PHISHING ANALYZER")

        print_line()

        print("1. Analyze Your Own Message")
        print("2. Analyze Sample Phishing Messages")
        print("3. View Phishing Safety Tips")
        print("4. About Project")
        print("5. Exit")

        print_line()

        choice = input("Enter your choice (1-5): ").strip()


        # ====================================================
        # OPTION 1
        # ====================================================

        if choice == "1":

            print("\n")
            print_line()
            print("              CUSTOM MESSAGE ANALYSIS")
            print_line()

            print(
                "Enter/paste the email or message below."
            )

            print(
                "Type END on a new line when finished."
            )

            print()

            lines = []

            while True:

                line = input()

                if line.strip().upper() == "END":

                    break

                lines.append(line)

            message = "\n".join(lines)

            if not message.strip():

                print("\n[!] Message cannot be empty.")

            else:

                result = analyzer.analyze(message)

                display_result(message, result)


        # ====================================================
        # OPTION 2
        # ====================================================

        elif choice == "2":

            print("\n")
            print_line()
            print("             SAMPLE MESSAGE ANALYSIS")
            print_line()

            for index, sample in enumerate(
                sample_messages,
                start=1
            ):

                print(
                    f"{index}. {sample['name']}"
                )

            print(
                f"{len(sample_messages) + 1}. Analyze All"
            )

            print(
                f"{len(sample_messages) + 2}. Back"
            )

            print_line()

            try:

                sample_choice = int(
                    input("Select an option: ")
                )

            except ValueError:

                print("\n[!] Please enter a valid number.")

                continue


            # Single sample

            if 1 <= sample_choice <= len(sample_messages):

                selected = sample_messages[
                    sample_choice - 1
                ]

                result = analyzer.analyze(
                    selected["message"]
                )

                display_result(
                    selected["message"],
                    result
                )


            # All samples

            elif sample_choice == len(sample_messages) + 1:

                for sample in sample_messages:

                    print("\n")
                    print("SAMPLE:", sample["name"])

                    result = analyzer.analyze(
                        sample["message"]
                    )

                    display_result(
                        sample["message"],
                        result
                    )


            elif sample_choice == len(sample_messages) + 2:

                continue

            else:

                print("\n[!] Invalid option.")


        # ====================================================
        # OPTION 3
        # ====================================================

        elif choice == "3":

            print("\n")
            print_line()
            print("                 PHISHING SAFETY TIPS")
            print_line()

            tips = [

                "Never click unexpected links in emails or messages.",

                "Check the sender's email address carefully.",

                "Be suspicious of urgent or threatening language.",

                "Never share your password, OTP, PIN, or CVV.",

                "Verify suspicious messages through official websites.",

                "Be careful with shortened URLs such as bit.ly.",

                "Check the website domain before entering credentials.",

                "Do not trust unexpected prizes or free offers.",

                "Use multi-factor authentication where possible.",

                "Report suspected phishing messages."
            ]

            for number, tip in enumerate(tips, start=1):

                print(f"{number}. {tip}")

            print_line()


        # ====================================================
        # OPTION 4
        # ====================================================

        elif choice == "4":

            print("\n")
            print_line()
            print("                    ABOUT PROJECT")
            print_line()

            print("Project: Phishing Awareness Analysis")
            print("Organization: DecodeLabs")
            print("Batch: 2026")
            print("Field: Cyber Security")

            print(
                "\nPurpose:"
            )

            print(
                "This project analyzes sample emails and messages "
                "to identify possible phishing attempts."
            )

            print(
                "\nThe analyzer checks:"
            )

            print("• Suspicious keywords")
            print("• Suspicious URLs")
            print("• Urgent language")
            print("• Requests for sensitive information")
            print("• Threats and fear-based language")
            print("• Unexpected rewards")
            print("• Suspicious domains")
            print("• Other phishing red flags")

            print_line()


        # ====================================================
        # OPTION 5
        # ====================================================

        elif choice == "5":

            print("\n")
            print_line()

            print(
                "Thank you for using the Phishing Awareness Analyzer!"
            )

            print(
                "Stay alert. Think before you click."
            )

            print_line()

            break


        else:

            print(
                "\n[!] Invalid choice. Please select 1-5."
            )


# ============================================================
#                    PROGRAM START
# ============================================================

if __name__ == "__main__":

    main()