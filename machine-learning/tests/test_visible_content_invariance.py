"""
test_visible_content_invariance.py

Phase 3.4 Visible-Content Invariance Test Suite for BANTAI.

Verifies that semantically identical human-visible email content produces
strictly identical canonical cleaned NLP representations across diverse delivery
and encoding formats:
    1. Plain text.
    2. Standard HTML body.
    3. Multipart/alternative MIME message.
    4. HTML with malicious hyperlink destinations in anchor hrefs.
    5. HTML with CSS url() and background images.
    6. HTML with 1x1 tracking pixels and image tags.
    7. HTML with hidden decoy elements (display:none, visibility:hidden, hidden).
    8. Adversarial malformed HTML with unclosed <head> enclosing <body>.
    9. Strict exclusion of synthetic placeholders ([URL], [EMAIL_ADDRESS]).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.preprocessing.content_cleaner import (
    CleanerConfig,
    ContentOnlyCleaner,
    clean_email_content,
)


class TestVisibleContentInvariance(unittest.TestCase):
    """
    Formal invariance test suite ensuring zero feature divergence across delivery formats.
    """

    def setUp(self) -> None:
        self.cleaner = ContentOnlyCleaner()

    def test_canonical_invariance_across_seven_variants(self) -> None:
        """
        Verify that 7 distinct representations of the same visible email body
        produce strictly identical canonical cleaned text.
        """
        canonical_text = (
            "Your account has been temporarily suspended. "
            "Please verify your credentials immediately to avoid service termination."
        )

        variants = {
            # Variant 1: Pure plain text
            "V1_plain": (
                "Your account has been temporarily suspended.\n\n"
                "Please verify your credentials immediately to avoid service termination."
            ),
            # Variant 2: Standard HTML body
            "V2_html_normal": (
                "<!DOCTYPE html><html><head><title>Notification</title></head>"
                "<body><p>Your account has been temporarily suspended.</p>"
                "<p>Please verify your credentials immediately to avoid service termination.</p>"
                "</body></html>"
            ),
            # Variant 3: Multipart/alternative MIME
            "V3_multipart_mime": (
                "From: security@alerts.org\r\n"
                "To: user@example.com\r\n"
                "Subject: Security Alert\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: multipart/alternative; boundary=\"BOUNDARY_XYZ\"\r\n"
                "\r\n"
                "--BOUNDARY_XYZ\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "\r\n"
                "Your account has been temporarily suspended.\n\n"
                "Please verify your credentials immediately to avoid service termination.\r\n"
                "--BOUNDARY_XYZ\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "\r\n"
                "<html><body><p>Your account has been temporarily suspended.</p>"
                "<p>Please verify your credentials immediately to avoid service termination.</p>"
                "</body></html>\r\n"
                "--BOUNDARY_XYZ--"
            ),
            # Variant 4: HTML with malicious anchor href destination
            "V4_anchor_href": (
                "<p>Your account has been temporarily suspended.</p>"
                "<p>Please <a href='https://attacker-domain.evil.com/login?token=abc98234729'>"
                "verify your credentials</a> immediately to avoid service termination.</p>"
            ),
            # Variant 5: HTML with CSS url() and background images
            "V5_css_url": (
                "<div style=\"background-image: url('https://tracker.evil.com/bg.png'); "
                "font-family: Arial, sans-serif;\">"
                "<p>Your account has been temporarily suspended.</p>"
                "<p>Please verify your credentials immediately to avoid service termination.</p>"
                "</div>"
            ),
            # Variant 6: HTML with 1x1 tracking pixel
            "V6_tracking_pixel": (
                "<p>Your account has been temporarily suspended.</p>"
                "<p>Please verify your credentials immediately to avoid service termination.</p>"
                "<img src='https://stat.tracker.com/pixel.gif?track_id=8831' width='1' height='1' alt='' />"
            ),
            # Variant 7: HTML with hidden decoy spam and script tags
            "V7_hidden_elements": (
                "<!-- System Alert Header -->"
                "<p>Your account has been temporarily suspended."
                "<span style='display:none'>free casino bonus cryptocurrency deposit</span></p>"
                "<script type='text/javascript'>console.log('malicious script execution');</script>"
                "<p>Please verify your credentials immediately to avoid service termination."
                "<span hidden>invisible SEO filler text</span></p>"
            ),
            # Variant 8: Adversarial unclosed <head> enclosing <body> (Phishing Pot stress pattern)
            "V8_unclosed_head": (
                "<!DOCTYPE html><html><head>"
                "<meta http-equiv='Content-Type' content='text/html; charset=utf-8'>"
                "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
                "<body style='background-color: #f4f4f4;'>"
                "<p>Your account has been temporarily suspended.</p>"
                "<p>Please verify your credentials immediately to avoid service termination.</p>"
                "</body></html>"
            ),
        }

        cleaned_outputs: dict[str, str] = {}
        for name, raw in variants.items():
            cleaned = self.cleaner.clean(raw)
            cleaned_outputs[name] = cleaned
            # Assert text matches expected paragraphs
            self.assertIn("Your account has been temporarily suspended.", cleaned, f"Failed on {name}")
            self.assertIn("Please verify your credentials immediately to avoid service termination.", cleaned, f"Failed on {name}")
            # Assert complete exclusion of tracking / markup / URL artifacts
            self.assertNotIn("evil.com", cleaned, f"URL leak on {name}")
            self.assertNotIn("tracker.com", cleaned, f"Tracker leak on {name}")
            self.assertNotIn("pixel.gif", cleaned, f"Pixel leak on {name}")
            self.assertNotIn("free casino", cleaned, f"Hidden text leak on {name}")
            self.assertNotIn("invisible SEO", cleaned, f"Hidden text leak on {name}")
            self.assertNotIn("console.log", cleaned, f"Script leak on {name}")
            self.assertNotIn("[URL]", cleaned, f"Placeholder leak on {name}")
            self.assertNotIn("[EMAIL_ADDRESS]", cleaned, f"Placeholder leak on {name}")

        # Strict textual equivalence: All variants must produce identical paragraph structure
        baseline_v1 = cleaned_outputs["V1_plain"]
        for name, output in cleaned_outputs.items():
            self.assertEqual(output, baseline_v1, f"Representation mismatch between V1 and {name}")

    def test_anchor_text_retained_destination_removed(self) -> None:
        """
        Verify that urgent phishing calls to action in anchor text are fully preserved
        while the destination URL is completely excised.
        """
        raw_html = (
            "<p>Dear valued customer,</p>"
            "<p>To prevent disruption, please "
            "<a href='https://phish-secure.ru/update-session.php?id=9928'>Click Here to Confirm Your Identity</a> "
            "within 24 hours.</p>"
        )
        cleaned = self.cleaner.clean(raw_html)
        self.assertIn("Click Here to Confirm Your Identity", cleaned)
        self.assertNotIn("phish-secure.ru", cleaned)
        self.assertNotIn("update-session.php", cleaned)
        self.assertNotIn("[URL]", cleaned)

    def test_raw_urls_excised_without_placeholder(self) -> None:
        """
        Verify that bare URLs in plain text are cleanly excised without leaving [URL] tokens.
        """
        raw_text = (
            "You can manage your subscription at https://account.company.com/manage.\n"
            "If you need assistance, visit www.company.com/support."
        )
        cleaned = self.cleaner.clean(raw_text)
        self.assertNotIn("https://account.company.com", cleaned)
        self.assertNotIn("www.company.com/support", cleaned)
        self.assertNotIn("[URL]", cleaned)
        self.assertIn("You can manage your subscription at .", cleaned)
        self.assertIn("If you need assistance, visit .", cleaned)

    def test_email_addresses_excised_without_placeholder(self) -> None:
        """
        Verify that email addresses are cleanly excised without leaving [EMAIL_ADDRESS] tokens.
        """
        raw_text = "Please send confirmations to billing-inquiries@mycorp.com immediately."
        cleaned = self.cleaner.clean(raw_text)
        self.assertNotIn("billing-inquiries@mycorp.com", cleaned)
        self.assertNotIn("[EMAIL_ADDRESS]", cleaned)
        self.assertEqual(cleaned, "Please send confirmations to immediately.")

    def test_adversarial_hidden_styles_matrix(self) -> None:
        """
        Verify that genuine hidden elements (display:none, visibility:hidden, hidden, aria-hidden) are stripped.
        """
        genuine_hidden_styles = [
            "<span style='display:none;'>Decoy Text 1</span>",
            "<span style='DISPLAY: NONE'>Decoy Text 2</span>",
            "<span style='display: none !important'>Decoy Text 3</span>",
            "<div style='visibility:hidden'>Decoy Text 4</div>",
            "<div style='VISIBILITY: HIDDEN'>Decoy Text 5</div>",
            "<p hidden>Decoy Text 6</p>",
            "<p aria-hidden='true'>Decoy Text 7</p>",
        ]
        for style_tag in genuine_hidden_styles:
            html_snippet = f"<p>Visible Message Before</p>{style_tag}<p>Visible Message After</p>"
            cleaned = self.cleaner.clean(html_snippet)
            self.assertIn("Visible Message Before", cleaned)
            self.assertIn("Visible Message After", cleaned)
            self.assertNotIn("Decoy Text", cleaned, f"Failed to filter hidden style: {style_tag}")

    def test_layout_reset_styles_preserve_visible_content(self) -> None:
        """
        Verify that MJML and HTML layout resets (e.g. font-size:0px, height:0)
        do not suppress human-readable body content.
        """
        layout_reset_tags = [
            "<td style='font-size:0px; line-height:0px; height:0;'>Layout Text 1</td>",
            "<div style='font-size: 0pt; height: 0;'>Layout Text 2</div>",
            "<table style='height:0px;'><tr><td>Layout Text 3</td></tr></table>",
        ]
        for layout_tag in layout_reset_tags:
            html_snippet = f"<p>Visible Message Before</p>{layout_tag}<p>Visible Message After</p>"
            cleaned = self.cleaner.clean(html_snippet)
            self.assertIn("Visible Message Before", cleaned)
            self.assertIn("Visible Message After", cleaned)
            self.assertTrue(
                "Layout Text" in cleaned,
                f"Layout reset style inadvertently suppressed readable content: {layout_tag}",
            )

    def test_phishing_pot_malformed_head_resilience(self) -> None:
        """
        Stress test reproducing the 868 Phishing Pot samples with unclosed <head>
        and multiple void <meta> tags.
        """
        pot_eml_snippet = """From: "Tax Refund Notification" <refund@tax-gov.org>
To: recipient@target.com
Subject: Notice of Outstanding Refund
Content-Type: text/html; charset=utf-8

<!DOCTYPE html><html lang="en"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<body style="background-color:rgb(241, 241, 241);">
    <p>Dear Taxpayer,</p>
    <p>We have determined that you are eligible to receive a tax refund of $482.50.</p>
    <p>Please submit your refund claim form before November 15, 2026.</p>
</body>
</html>"""
        cleaned = self.cleaner.clean(pot_eml_snippet)
        self.assertIn("Dear Taxpayer,", cleaned)
        self.assertIn("We have determined that you are eligible to receive a tax refund of $482.50.", cleaned)
        self.assertIn("Please submit your refund claim form before November 15, 2026.", cleaned)
        self.assertNotIn("tax-gov.org", cleaned)
        self.assertNotIn("Content-Type", cleaned)

    def test_phishing_pot_unclosed_head_without_body_recovery(self) -> None:
        """
        Stress test verifying recovery of the 5 malformed Phishing Pot messages
        with unclosed <head> and completely omitted <body> tag, while strictly preventing
        trailing unclosed <style> dictionary spam and <applet> Bayesian poisoning.
        """
        # Pattern 1: unclosed head followed directly by <center> / <h3> (sample-3553 / sample-7273)
        html_unclosed_head = (
            "<!DOCTYPE html><html><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'>"
            "<center><h3>The Best Site to Meet Hot Russian Ladies</h3>"
            "<a href='https://dating-malware.com/click'>Click Here</a> to remove yourself from our emails list.</center>"
            "<style type='text/css'>estafas finales semillas condominium random dictionary spam</style>"
        )
        cleaned = self.cleaner.clean(html_unclosed_head)
        self.assertIn("The Best Site to Meet Hot Russian Ladies", cleaned)
        self.assertIn("Click Here to remove yourself from our emails list.", cleaned)
        self.assertNotIn("dating-malware.com", cleaned)
        self.assertNotIn("estafas", cleaned)
        self.assertNotIn("condominium", cleaned)

        # Pattern 2: unclosed head with <thead>, followed by <applet> Bayesian text (sample-8527)
        html_applet_hazard = (
            "<html><head><meta content='text/html;'><style>.x{color:blue;}</style>"
            "<thead><h5>Storage Limit Reached Files Removal Scheduled Monday</h5>"
            "<applet>Welcome to Garagiste! Your curated wine experience begins today.</applet>"
            "<q style='display:none'>Hidden Bayesian Poisoning Newsletter</q>"
        )
        cleaned_hazard = self.cleaner.clean(html_applet_hazard)
        self.assertIn("Storage Limit Reached Files Removal Scheduled Monday", cleaned_hazard)
        self.assertNotIn("Garagiste", cleaned_hazard)
        self.assertNotIn("curated wine", cleaned_hazard)
        self.assertNotIn("Hidden Bayesian", cleaned_hazard)


if __name__ == "__main__":
    unittest.main()

