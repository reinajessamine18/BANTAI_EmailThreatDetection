"""
test_content_cleaner.py

Comprehensive unit tests for ContentOnlyCleaner.
Tests plain-text, MIME, HTML, anchor text, URL/email handling,
whitespace/punctuation normalization, Unicode, and determinism.
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


class TestContentOnlyCleaner(unittest.TestCase):
    """Unit test suite for the general-purpose content-only email cleaner."""

    def setUp(self) -> None:
        self.default_cleaner = ContentOnlyCleaner()

    def test_plain_text_basic(self) -> None:
        """Test plain text input with simple text and paragraphs."""
        raw = "Hello team,\n\nPlease review the attached quarterly summary.\n\nBest regards,\nAlice"
        cleaned = self.default_cleaner.clean(raw)
        self.assertIn("Hello team,", cleaned)
        self.assertIn("Please review the attached quarterly summary.", cleaned)
        self.assertIn("Best regards,\nAlice", cleaned)

    def test_empty_and_none_input(self) -> None:
        """Test that empty or None inputs return empty string safely."""
        self.assertEqual(self.default_cleaner.clean(None), "")
        self.assertEqual(self.default_cleaner.clean(""), "")
        self.assertEqual(self.default_cleaner.clean("   \n\n\t  "), "")

    def test_html_tag_stripping(self) -> None:
        """Test that HTML tags are removed and text is extracted."""
        html_input = "<html><body><h1>Urgent Notice</h1><p>Your account is locked.</p></body></html>"
        cleaned = self.default_cleaner.clean(html_input)
        self.assertNotIn("<html>", cleaned)
        self.assertNotIn("<h1>", cleaned)
        self.assertNotIn("<p>", cleaned)
        self.assertIn("Urgent Notice", cleaned)
        self.assertIn("Your account is locked.", cleaned)

    def test_html_script_and_style_removal(self) -> None:
        """Test that <script> and <style> tags and their inner contents are discarded."""
        html_input = """
        <html>
        <head>
            <style>body { font-size: 14px; color: red; }</style>
            <script>alert('malicious script');</script>
        </head>
        <body>
            <p>Legitimate visible warning text.</p>
            <script type="text/javascript">document.write('hidden tracking');</script>
        </body>
        </html>
        """
        cleaned = self.default_cleaner.clean(html_input)
        self.assertNotIn("font-size", cleaned)
        self.assertNotIn("alert", cleaned)
        self.assertNotIn("malicious script", cleaned)
        self.assertNotIn("document.write", cleaned)
        self.assertIn("Legitimate visible warning text.", cleaned)

    def test_anchor_text_preservation(self) -> None:
        """Test that anchor text inside <a> tags is preserved when URLs are removed."""
        html_input = '<p>Please <a href="https://malicious-phish.com/login?id=99">Click Here to Verify</a> your password.</p>'
        cleaned = self.default_cleaner.clean(html_input)
        self.assertIn("Click Here to Verify", cleaned)
        self.assertNotIn("malicious-phish.com", cleaned)
        self.assertNotIn("[URL]", cleaned)

        # Placeholder config still emits [URL] when requested
        cleaner_p = ContentOnlyCleaner(CleanerConfig(url_strategy="placeholder"))
        cleaned_p = cleaner_p.clean(html_input)
        self.assertIn("Click Here to Verify", cleaned_p)
        self.assertIn("[URL]", cleaned_p)

    def test_url_handling_strategies(self) -> None:
        """Test placeholder, remove, and keep strategies for URLs."""
        raw = "Visit https://secure.bank.com/portal/login to update details. Also see www.helpdesk.org/faq."

        # 1. Placeholder
        cleaner_placeholder = ContentOnlyCleaner(CleanerConfig(url_strategy="placeholder"))
        res_placeholder = cleaner_placeholder.clean(raw)
        self.assertIn("[URL]", res_placeholder)
        self.assertNotIn("https://secure.bank.com", res_placeholder)
        self.assertNotIn("www.helpdesk.org", res_placeholder)
        self.assertIn("Visit [URL] to update details. Also see [URL].", res_placeholder)

        # 2. Remove (now default)
        cleaner_remove = ContentOnlyCleaner(CleanerConfig(url_strategy="remove"))
        res_remove = cleaner_remove.clean(raw)
        self.assertNotIn("[URL]", res_remove)
        self.assertNotIn("https://secure.bank.com", res_remove)
        self.assertEqual(self.default_cleaner.clean(raw), res_remove)
        self.assertIn("Visit to update details. Also see .", res_remove)

        # 3. Keep
        cleaner_keep = ContentOnlyCleaner(CleanerConfig(url_strategy="keep"))
        res_keep = cleaner_keep.clean(raw)
        self.assertIn("https://secure.bank.com/portal/login", res_keep)
        self.assertIn("www.helpdesk.org/faq", res_keep)

    def test_url_trailing_punctuation_preserved(self) -> None:
        """Test that trailing sentence punctuation is not swallowed by URL abstraction."""
        raw = "Log in at https://myportal.com/auth. Then notify us at https://myportal.com/help!"
        cleaned = self.default_cleaner.clean(raw)
        self.assertEqual(cleaned, "Log in at . Then notify us at !")

        cleaner_p = ContentOnlyCleaner(CleanerConfig(url_strategy="placeholder"))
        cleaned_p = cleaner_p.clean(raw)
        self.assertIn("[URL].", cleaned_p)
        self.assertIn("[URL]!", cleaned_p)

    def test_email_handling_strategies(self) -> None:
        """Test placeholder, remove, and keep strategies for email addresses."""
        raw = "Contact support at billing-dept@company.com for inquiries or reach admin@security.org."

        # 1. Placeholder
        cleaner_placeholder = ContentOnlyCleaner(CleanerConfig(email_strategy="placeholder"))
        res_placeholder = cleaner_placeholder.clean(raw)
        self.assertIn("[EMAIL_ADDRESS]", res_placeholder)
        self.assertNotIn("billing-dept@company.com", res_placeholder)
        self.assertNotIn("admin@security.org", res_placeholder)

        # 2. Remove (now default)
        cleaner_remove = ContentOnlyCleaner(CleanerConfig(email_strategy="remove"))
        res_remove = cleaner_remove.clean(raw)
        self.assertNotIn("[EMAIL_ADDRESS]", res_remove)
        self.assertNotIn("billing-dept@company.com", res_remove)
        self.assertEqual(self.default_cleaner.clean(raw), res_remove)
        self.assertIn("Contact support at for inquiries", res_remove)

        # 3. Keep
        cleaner_keep = ContentOnlyCleaner(CleanerConfig(email_strategy="keep"))
        res_keep = cleaner_keep.clean(raw)
        self.assertIn("billing-dept@company.com", res_keep)

    def test_mime_email_parsing(self) -> None:
        """Test that raw MIME formatted email headers are excluded and body is extracted."""
        mime_msg = (
            "From: spoofed-security@bank.com\r\n"
            "To: victim@domain.com\r\n"
            "Subject: Account Suspension Notice\r\n"
            "Date: Wed, 04 Nov 2026 12:00:00 +0000\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Dear customer,\n\nYour account has been suspended due to suspicious activity.\n"
            "Please click https://phish-site.com/auth immediately."
        )
        cleaned = self.default_cleaner.clean(mime_msg)
        # Headers must NOT leak into cleaned output
        self.assertNotIn("From: spoofed-security", cleaned)
        self.assertNotIn("To: victim@domain.com", cleaned)
        self.assertNotIn("Subject: Account Suspension", cleaned)
        self.assertNotIn("Content-Type: text/plain", cleaned)
        # Body text must be present
        self.assertIn("Dear customer,", cleaned)
        self.assertIn("Your account has been suspended", cleaned)
        self.assertNotIn("https://phish-site.com", cleaned)

    def test_multipart_mime_prefer_plain(self) -> None:
        """Test that multipart/alternative MIME emails extract the readable body."""
        multipart_msg = (
            "From: newsletter@news.org\r\n"
            "To: member@domain.com\r\n"
            "Subject: Weekly Digest\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: multipart/alternative; boundary=\"BOUNDARY123\"\r\n"
            "\r\n"
            "--BOUNDARY123\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "This is the plain text version of the weekly newsletter.\r\n"
            "--BOUNDARY123\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            "<html><body><p>This is the HTML version.</p></body></html>\r\n"
            "--BOUNDARY123--"
        )
        cleaned = self.default_cleaner.clean(multipart_msg)
        self.assertIn("This is the plain text version of the weekly newsletter.", cleaned)
        self.assertNotIn("--BOUNDARY123", cleaned)
        self.assertNotIn("Content-Type:", cleaned)

    def test_punctuation_spacing_normalization(self) -> None:
        """Test normalization of pre-tokenized spacing around punctuation."""
        spaced_text = "enron capital & trade corp . from : \" eileen \" 05 / 29 / 2001 . don ' t miss it ."
        cleaned = self.default_cleaner.clean(spaced_text)
        self.assertIn("corp.", cleaned)
        self.assertIn("don't miss it.", cleaned)
        self.assertNotIn("corp .", cleaned)
        self.assertNotIn("don ' t", cleaned)

    def test_spaced_email_normalization(self) -> None:
        """Test that pre-tokenized spaced email addresses 'user @ enron . com' are normalized."""
        spaced_email = "Please contact daren . farmer @ enron . com regarding the pipeline deal."
        cleaned = self.default_cleaner.clean(spaced_email)
        self.assertNotIn("daren . farmer @ enron . com", cleaned)
        self.assertNotIn("[EMAIL_ADDRESS]", cleaned)
        self.assertIn("regarding the pipeline deal.", cleaned)

        # Placeholder config emits [EMAIL_ADDRESS] when requested
        cleaner_p = ContentOnlyCleaner(CleanerConfig(email_strategy="placeholder"))
        cleaned_p = cleaner_p.clean(spaced_email)
        self.assertIn("[EMAIL_ADDRESS]", cleaned_p)

    def test_unclosed_head_recovery(self) -> None:
        """Test that unclosed <head> enclosing <body> recovers visible body text."""
        malformed = (
            "<!DOCTYPE html><html><head>"
            "<meta http-equiv='Content-Type' content='text/html; charset=utf-8'>"
            "<body style='background-color: white;'>"
            "<p>Urgent account verification required.</p>"
            "</body></html>"
        )
        cleaned = self.default_cleaner.clean(malformed)
        self.assertIn("Urgent account verification required.", cleaned)

    def test_hidden_elements_style_removal(self) -> None:
        """Test that genuine hidden elements (display:none, visibility:hidden, hidden, aria-hidden) are excluded."""
        html_input = (
            "<div>"
            "<p>Visible alert text.</p>"
            "<span style='display:none'>Hidden secret spam words</span>"
            "<div hidden>Another hidden decoy text</div>"
            "<p style='visibility:hidden'>Invisible paragraph</p>"
            "<p aria-hidden='true'>Screen-reader hidden text</p>"
            "<p>End of message.</p>"
            "</div>"
        )
        cleaned = self.default_cleaner.clean(html_input)
        self.assertIn("Visible alert text.", cleaned)
        self.assertIn("End of message.", cleaned)
        self.assertNotIn("Hidden secret spam words", cleaned)
        self.assertNotIn("Another hidden decoy text", cleaned)
        self.assertNotIn("Invisible paragraph", cleaned)
        self.assertNotIn("Screen-reader hidden text", cleaned)

    def test_mjml_layout_cells_preserved(self) -> None:
        """Test that MJML structural layout resets (font-size:0px, height:0) do not suppress readable content."""
        html_input = (
            "<table><tr>"
            "<td style='font-size:0px;line-height:0px;height:0;mso-line-height-rule:exactly;'>"
            "<span>Readable MJML Layout Content</span>"
            "</td>"
            "</tr></table>"
        )
        cleaned = self.default_cleaner.clean(html_input)
        self.assertIn("Readable MJML Layout Content", cleaned)

    def test_void_tags_meta_link_depth(self) -> None:
        """Test that void tags <meta> and <link> do not increment ignore depth permanently."""
        html_input = (
            "<html><head><meta charset='utf-8'><link rel='stylesheet' href='style.css'></head>"
            "<body><meta name='viewport' content='width=device-width'><p>Visible text after void tags.</p></body></html>"
        )
        cleaned = self.default_cleaner.clean(html_input)
        self.assertIn("Visible text after void tags.", cleaned)

    def test_css_urls_and_tracking_pixels_removal(self) -> None:
        """Test that inline CSS url() and 1x1 tracking pixels do not leak into text."""
        html_input = (
            "<div style=\"background-image: url('https://tracker.com/bg.png');\">"
            "<p>Legitimate body content.</p>"
            "<img src='https://tracker.com/pixel.gif?id=123' width='1' height='1' alt='' />"
            "</div>"
        )
        cleaned = self.default_cleaner.clean(html_input)
        self.assertIn("Legitimate body content.", cleaned)
        self.assertNotIn("tracker.com", cleaned)
        self.assertNotIn("bg.png", cleaned)
        self.assertNotIn("pixel.gif", cleaned)

    def test_html_entity_decoding(self) -> None:
        """Test HTML entities are properly unescaped to readable natural characters."""
        text = "AT&amp;T &quot;Online Account&quot; &#39;Special Offer&#39; &euro;100 &pound;50"
        cleaned = self.default_cleaner.clean(text)
        self.assertIn("AT&T", cleaned)
        self.assertIn('"Online Account"', cleaned)
        self.assertIn("'Special Offer'", cleaned)
        self.assertIn("€100", cleaned)
        self.assertIn("£50", cleaned)

    def test_unicode_handling(self) -> None:
        """Test non-ASCII Greek, accented Latin, and emoji characters are handled safely."""
        unicode_text = "Attention: Résumé validation for Dr. Müller. Greek: α β γ. Emoji: ⚠️ Important Alert!"
        cleaned = self.default_cleaner.clean(unicode_text)
        self.assertIn("Résumé", cleaned)
        self.assertIn("Müller", cleaned)
        self.assertIn("α β γ", cleaned)
        self.assertIn("Important Alert!", cleaned)

    def test_case_preservation_by_default(self) -> None:
        """Test that original capitalization is preserved by default."""
        text = "URGENT NOTICE: PayPal Security Team Requires Action."
        cleaned = self.default_cleaner.clean(text)
        self.assertEqual(cleaned, text)

    def test_lowercase_configuration(self) -> None:
        """Test explicit lowercasing when requested."""
        text = "URGENT NOTICE: PayPal Security Team Requires Action."
        cleaner = ContentOnlyCleaner(CleanerConfig(lowercase=True))
        cleaned = cleaner.clean(text)
        self.assertEqual(cleaned, text.lower())

    def test_paragraph_and_sentence_preservation(self) -> None:
        """Test that secondary sentences and distinct paragraphs are preserved."""
        text = (
            "Paragraph one introduces the proposal.\n\n"
            "Paragraph two contains secondary context and multiple details. "
            "A second sentence follows within the paragraph.\n\n"
            "Paragraph three concludes the message."
        )
        cleaned = self.default_cleaner.clean(text)
        self.assertIn("Paragraph one introduces the proposal.", cleaned)
        self.assertIn("Paragraph two contains secondary context and multiple details.", cleaned)
        self.assertIn("A second sentence follows within the paragraph.", cleaned)
        self.assertIn("Paragraph three concludes the message.", cleaned)
        self.assertIn("\n\n", cleaned)

    def test_determinism(self) -> None:
        """Test that cleaning the exact same input produces identical output across multiple calls."""
        text = (
            "<p>Dear customer,</p><p>Visit <a href='https://bank.com'>https://bank.com</a> "
            "or email help@bank.com. Don ' t delay !</p>"
        )
        out1 = self.default_cleaner.clean(text)
        out2 = self.default_cleaner.clean(text)
        out3 = self.default_cleaner.clean(text)
        self.assertEqual(out1, out2)
        self.assertEqual(out2, out3)


if __name__ == "__main__":
    unittest.main()

