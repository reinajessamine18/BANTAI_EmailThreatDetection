"""
test_dataset_sanitizer.py

Comprehensive unit and regression tests for DatasetSanitizer.
Tests Nazario mbox quarantine, base64 detection, Enron forwarding headers,
SpamAssassin Mailman footers, and regression examples across all sources.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.preprocessing.content_cleaner import CleanerConfig, ContentOnlyCleaner
from src.preprocessing.dataset_sanitizer import DatasetSanitizer


class TestDatasetSanitizer(unittest.TestCase):
    """Unit test suite for dataset-specific sanitization utilities."""

    def setUp(self) -> None:
        self.sanitizer = DatasetSanitizer()

    def test_nazario_mbox_quarantine(self) -> None:
        """Test that Nazario mbox folder internal metadata records are quarantined."""
        row = {
            "subject": "DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA",
            "body": "This text is part of the internal format of your mail folder. Do not delete.",
        }
        result = self.sanitizer.sanitize_nazario_record(row)
        self.assertTrue(result.is_quarantined)
        self.assertEqual(result.quarantine_reason, "mbox_metadata_folder_header")
        self.assertEqual(result.cleaned_text, "")
        self.assertIn("quarantine:mbox_metadata", result.flags)

    def test_nazario_base64_extreme_outlier_quarantine(self) -> None:
        """Test that extreme base64 attachment outliers (>500,000 chars) are quarantined."""
        fake_base64_block = ("A" * 70 + "\n") * 8000  # > 560,000 chars
        row = {
            "subject": "Account Attachment Notice",
            "body": f"Content-Transfer-Encoding: base64\n\n{fake_base64_block}",
        }
        result = self.sanitizer.sanitize_nazario_record(row)
        self.assertTrue(result.is_quarantined)
        self.assertEqual(result.quarantine_reason, "extreme_base64_attachment_outlier")
        self.assertEqual(result.cleaned_text, "")

    def test_nazario_valid_phishing_cleaned(self) -> None:
        """Test that valid Nazario phishing emails are cleaned without removing natural words."""
        row = {
            "subject": "Urgent Security Alert for your Online Banking",
            "body": "Dear customer,\n\nWe detected suspicious activity on your account. "
                    "Please visit https://chase-bank-verify.com/login.html to update your password. "
                    "Thank you,\nSecurity Team",
        }
        result = self.sanitizer.sanitize_nazario_record(row)
        self.assertFalse(result.is_quarantined)
        self.assertIn("Dear customer,", result.cleaned_text)
        self.assertIn("We detected suspicious activity on your account.", result.cleaned_text)
        # Default strategy is remove: URL excised without placeholder token
        self.assertNotIn("[URL]", result.cleaned_text)
        self.assertNotIn("https://chase-bank-verify.com", result.cleaned_text)

    def test_enron_forwarded_header_stripping(self) -> None:
        """Test that Enron internal forwarded routing header lines are stripped when enabled."""
        row = {
            "subject": "re: gas pipeline deal",
            "body": "- - - - - forwarded by sabrae zajac / hou / ect on 05 / 30 / 2001 12 : 07 pm - - - - -\n"
                    "enron capital & trade resources corp .\n"
                    "Daren, please check the June delivery schedule for Houston gas contracts.",
        }
        result = self.sanitizer.sanitize_enron_record(row, strip_forwarding_headers=True)
        self.assertFalse(result.is_quarantined)
        self.assertNotIn("forwarded by sabrae zajac", result.cleaned_text)
        self.assertIn("enron capital & trade resources corp.", result.cleaned_text)
        self.assertIn("Daren, please check the June delivery schedule for Houston gas contracts.", result.cleaned_text)
        self.assertIn("sanitized:forwarded_header_stripped", result.flags)
        self.assertIn("retained:enron_term", result.flags)

    def test_enron_preserves_meaningful_terms(self) -> None:
        """Test that 'enron' and business terminology are preserved in Enron ham."""
        row = {
            "subject": "enron commercial meeting",
            "body": "The meeting with Enron senior management is scheduled for Thursday at 2 PM. "
                    "Contact vince.kaminski@enron.com if you have questions.",
        }
        result = self.sanitizer.sanitize_enron_record(row)
        self.assertIn("The meeting with Enron senior management is scheduled for Thursday at 2 PM.", result.cleaned_text)
        # Default strategy is remove: email excised without placeholder
        self.assertNotIn("[EMAIL_ADDRESS]", result.cleaned_text)
        self.assertNotIn("vince.kaminski@enron.com", result.cleaned_text)

    def test_spamassassin_mailman_footer_stripping(self) -> None:
        """Test that SpamAssassin Mailman footer boilerplate is stripped while body is kept."""
        row = {
            "subject": "Linux kernel patch discussion",
            "body": "Hi team,\n\nI tested the new Linux memory management patch on RedHat 8.0.\n"
                    "It works reliably with no kernel panics.\n\n"
                    "-------------------------------------------------------\n"
                    "This SF.net email is sponsored by: ThinkGeek\n"
                    "Welcome to geek heaven.\n"
                    "https://lists.sourceforge.net/lists/listinfo/spamassassin-devel\n",
        }
        result = self.sanitizer.sanitize_spamassassin_record(row, strip_mailman_footers=True)
        self.assertFalse(result.is_quarantined)
        self.assertIn("I tested the new Linux memory management patch on RedHat 8.0.", result.cleaned_text)
        self.assertIn("It works reliably with no kernel panics.", result.cleaned_text)
        # Footer block must be gone
        self.assertNotIn("ThinkGeek", result.cleaned_text)
        self.assertNotIn("listinfo/spamassassin-devel", result.cleaned_text)
        self.assertIn("retained:linux_term", result.flags)
        self.assertIn("sanitized:mailman_footer_stripped", result.flags)

    def test_regression_representative_nazario(self) -> None:
        """Regression test using representative sanitized Nazario email snippet."""
        raw_nazario = (
            "Dear jose@monkey.org,\n\n"
            "We have received notice that your mailbox has reached 98% capacity.\n"
            "Please click <a href='https://auth.monkey-mail.org/update'>Update Mailbox</a> "
            "to prevent service disruption.\n\n"
            "Thank you,\nWebmail Administrator"
        )
        row = {"subject": "Urgent Mailbox Upgrade", "body": raw_nazario}
        result = self.sanitizer.sanitize_nazario_record(row)
        self.assertFalse(result.is_quarantined)
        # In remove mode, email is removed without placeholder
        self.assertNotIn("[EMAIL_ADDRESS]", result.cleaned_text)
        self.assertNotIn("jose@monkey.org", result.cleaned_text)
        self.assertIn("We have received notice that your mailbox has reached 98% capacity.", result.cleaned_text)
        self.assertIn("Update Mailbox", result.cleaned_text)
        self.assertNotIn("[URL]", result.cleaned_text)
        self.assertNotIn("https://auth.monkey-mail.org", result.cleaned_text)

        # In explicit placeholder mode, [EMAIL_ADDRESS] and [URL] are generated
        sanitizer_p = DatasetSanitizer(
            cleaner=ContentOnlyCleaner(CleanerConfig(url_strategy="placeholder", email_strategy="placeholder"))
        )
        result_p = sanitizer_p.sanitize_nazario_record(row)
        self.assertIn("[EMAIL_ADDRESS]", result_p.cleaned_text)
        self.assertIn("[URL]", result_p.cleaned_text)

    def test_regression_representative_enron(self) -> None:
        """Regression test using representative sanitized Enron email snippet."""
        raw_enron = (
            "louise -\n"
            "here are the latest price curves for iferc 160 , 000 enron 110 , 625 .\n"
            "let ' s meet at 10 : 00 am in eb 32 c 2 .\n"
            "vince"
        )
        row = {"subject": "price curves", "body": raw_enron}
        result = self.sanitizer.sanitize_enron_record(row)
        self.assertFalse(result.is_quarantined)
        self.assertIn("louise -", result.cleaned_text)
        self.assertIn("enron 110, 625.", result.cleaned_text)
        self.assertIn("let's meet at 10: 00 am in eb 32 c 2.", result.cleaned_text)
        self.assertIn("vince", result.cleaned_text)

    def test_regression_representative_spamassassin(self) -> None:
        """Regression test using representative sanitized SpamAssassin email snippet."""
        raw_sa = (
            "On Wed, 21 Aug 2002, Chris Garrigues wrote:\n"
            "> I can't reproduce this error. For me it is very repeatable.\n\n"
            "The patch applies cleanly on Linux 2.4.19 with gcc 3.2.\n\n"
            "_______________________________________________\n"
            "Exmh-workers mailing list\n"
            "Exmh-workers@redhat.com\n"
            "https://listman.redhat.com/mailman/listinfo/exmh-workers\n"
        )
        row = {"subject": "[Exmh-workers] Patch testing", "body": raw_sa}
        result = self.sanitizer.sanitize_spamassassin_record(row)
        self.assertFalse(result.is_quarantined)
        self.assertIn("On Wed, 21 Aug 2002, Chris Garrigues wrote:", result.cleaned_text)
        self.assertIn("The patch applies cleanly on Linux 2.4.19 with gcc 3.2.", result.cleaned_text)
        self.assertNotIn("listinfo/exmh-workers", result.cleaned_text)

    def test_nazario_preserves_authentic_domain_personalization_and_jose(self) -> None:
        """Test that authentic monkey.org visible body prose and 'San Jose, CA' are preserved in default mode."""
        raw_nazario = (
            "Dear jose@monkey.org,\n\n"
            "Urgent notice to all monkey.org users: the monkey.org support team has detected unusual logins.\n"
            "Please visit https://auth.update-service.com/login to verify your credentials.\n\n"
            "PayPal Inc., 2211 North First Street, San Jose, CA 95131."
        )
        row = {"subject": "Urgent monkey.org Security Alert", "body": raw_nazario}
        result = self.sanitizer.sanitize_nazario_record(row)
        self.assertFalse(result.is_quarantined)
        # Email address is removed by cleaner
        self.assertNotIn("jose@monkey.org", result.cleaned_text)
        # Raw URL is removed by cleaner
        self.assertNotIn("https://auth.update-service.com", result.cleaned_text)
        # Visible lure phrasing is preserved intact
        self.assertIn("all monkey.org users", result.cleaned_text)
        self.assertIn("monkey.org support team", result.cleaned_text)
        # Natural location and name terms are preserved
        self.assertIn("San Jose, CA", result.cleaned_text)
        self.assertIn("jose", result.cleaned_text.lower())
        # Audit flag for recipient domain personalization is recorded
        self.assertIn("audit:recipient_domain_personalization_present", result.flags)

    def test_nazario_collector_domain_scrubbed_and_jose_preserved(self) -> None:
        """Test that monkey.org collector domains can be optionally scrubbed while 'jose' (San Jose, CA) is preserved."""
        raw_nazario = (
            "Dear customer,\n\n"
            "Your PayPal account access has been limited due to suspicious activity from host mail.monkey.org.\n"
            "Please verify your identity.\n\n"
            "PayPal Inc., 2211 North First Street, San Jose, CA 95131."
        )
        row = {"subject": "Urgent PayPal Security Notice", "body": raw_nazario}
        result = self.sanitizer.sanitize_nazario_record(row, strip_collector_domain=True)
        self.assertFalse(result.is_quarantined)
        self.assertNotIn("monkey.org", result.cleaned_text)
        self.assertNotIn("mail.monkey.org", result.cleaned_text)
        self.assertIn("sanitized:collector_domain_stripped", result.flags)
        # Natural location and name terms like 'San Jose, CA' must be preserved
        self.assertIn("San Jose, CA", result.cleaned_text)
        self.assertIn("jose", result.cleaned_text.lower())

    def test_phishing_pot_honeypot_decoy_stripped(self) -> None:
        """Test that honeypot decoy addresses (@pot) are scrubbed while natural body text is preserved."""
        raw_pot = (
            "From: Security Team <security@cloud-service.com>\n"
            "To: phishing@pot\n"
            "Subject: Account Action Required\n\n"
            "Hello,\n\n"
            "We detected an unrecognized login attempt for user phishing@pot. "
            "Claim your potential account security jackpot bonus now.\n"
            "Thank you."
        )
        result = self.sanitizer.sanitize_phishing_pot_record(raw_pot, strip_honeypot_decoys=True)
        self.assertFalse(result.is_quarantined)
        self.assertNotIn("phishing@pot", result.cleaned_text)
        self.assertIn("sanitized:honeypot_decoy_stripped", result.flags)
        # Natural words containing 'pot' must NOT be affected
        self.assertIn("potential", result.cleaned_text)
        self.assertIn("jackpot", result.cleaned_text)
        self.assertIn("We detected an unrecognized login attempt for user", result.cleaned_text)


if __name__ == "__main__":
    unittest.main()

