import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml"))

from attachment_features import extract_attachment_features
from features import _header_features, extract_email_text_features, fuse_email_features
from infer import _predict_attachment, _predict_email, _validate_email_payload, app
from settings import FEATURE_DIMENSIONS
from train import _url_host_group


EXACT_REPORTED_EMAIL = """From: "PayPal Security" <security-alert@paypa1-account-update.xyz>
Received-SPF: fail
Subject: URGENT: Your PayPal Account Has Been Suspended! Verify Identity

Dear Valued Customer,
We detected multiple unauthorized sign-in attempts to your PayPal account from unknown IP 194.26.29.11.
For your safety, YOUR ACCOUNT HAS BEEN TEMPORARILY SUSPENDED.
You must verify your password and banking details within 24 hours to prevent permanent account termination.
Click here immediately: http://verify-paypal-user.security-update.xyz/login
Urgent action required!
Security Team
PayPal Inc."""


LEGITIMATE_EMAILS = [
    ("sarah.miller@acme-corp.com", "Project kickoff agenda", "Authentication-Results: spf=pass dkim=pass dmarc=pass\nPlease review the agenda before Monday's meeting."),
    ("cloud-noreply@google.com", "Monthly billing statement", "Authentication-Results: spf=pass dkim=pass dmarc=pass\nYour usage statement is available in the Cloud Console."),
    ("notifications@github.com", "Pull request review", "Authentication-Results: spf=pass dkim=pass dmarc=pass\nA teammate requested your review on the repository pull request."),
    ("calendar@google.com", "Team calendar update", "Authentication-Results: spf=pass dkim=pass dmarc=pass\nThe weekly team meeting has moved to Tuesday at 10:00 AM."),
    ("receipts@amazon.com", "Order receipt", "Authentication-Results: spf=pass dkim=pass dmarc=pass\nThank you for your purchase. Your order will arrive next week."),
    ("hr@acme-corp.com", "Benefits information", "Authentication-Results: spf=pass dkim=pass dmarc=pass\nThe annual benefits guide is available on the company intranet."),
]


PHISHING_EMAILS = [
    ("security@account-verify.xyz", "URGENT account suspension", "Your account will be deleted today. Verify your password and click here immediately: http://account-verify.xyz/login"),
    ("support@micros0ft-security.top", "Action required: verify identity", "Your mailbox is suspended. Confirm your credentials within 12 hours or access will be terminated: http://micros0ft-security.top/verify"),
    ("billing@paypa1-alert.link", "Payment failed", "Your payment failed and your account is locked. Login now to update your banking details: http://paypa1-alert.link/update"),
    ("admin@service-help.club", "Security alert", "Unauthorized sign-in detected. Click here to restore your account before permanent deletion: http://service-help.club/restore"),
]


class PhishingDetectionTests(unittest.TestCase):
    def test_indicator_features_cover_reported_language(self):
        features = extract_email_text_features(EXACT_REPORTED_EMAIL)
        self.assertEqual(len(features), FEATURE_DIMENSIONS["email_text"])
        self.assertGreater(features[11], 0)  # urgency
        self.assertGreater(features[12], 0)  # threat/deletion/suspension
        self.assertGreater(features[13], 0)  # account verification
        self.assertGreater(features[14], 0)  # credentials
        self.assertGreater(features[15], 0)  # CTA
        self.assertEqual(features[17], 1)  # urgency + threat
        self.assertEqual(features[18], 1)  # account + credential
        self.assertEqual(features[21], 1)  # SPF failure

    def test_authentication_results_in_message_body_are_not_trusted(self):
        body = "A copied message says:\nAuthentication-Results: spf=pass dkim=pass dmarc=pass"
        self.assertEqual(_header_features(body), (0.0, 0.0, 0.0))
        self.assertEqual(extract_email_text_features(body)[22], 0)

    def test_authentication_results_in_header_block_are_parsed(self):
        raw_email = "From: person@example.com\nAuthentication-Results: spf=pass dkim=pass dmarc=pass\n\nHello"
        self.assertEqual(_header_features(raw_email), (0.0, 1.0, 0.0))

    def test_url_validation_groups_paths_by_hostname(self):
        self.assertEqual(
            _url_host_group("https://www.example.com/path?a=1"),
            _url_host_group("http://example.com/another-path"),
        )

    def test_macro_enabled_documents_are_not_clean_by_extension_alone(self):
        features, diagnostics = extract_attachment_features(b"", "invoice.docm")
        self.assertEqual(len(features), 30)
        self.assertEqual(diagnostics["features"]["is_macro_ext"], 1)

    def test_attachment_inference_overrides_and_normalizes_probabilities(self):
        minimal_pe = bytearray(128)
        minimal_pe[:2] = b"MZ"
        minimal_pe[0x3C:0x40] = (64).to_bytes(4, byteorder="little")
        minimal_pe[64:68] = b"PE\x00\x00"
        cases = [
            (b"", "invoice.docm", "Suspicious"),
            (b"", "invoice.pdf.exe", "Malicious"),
            (bytes(minimal_pe), "invoice.pdf", "Malicious"),
            (b"%PDF-1.4\n", "invoice.pdf", "Safe"),
        ]
        for content, filename, expected in cases:
            with self.subTest(filename=filename, content=content[:4]):
                result = _predict_attachment(content, filename)
                probabilities = result["probabilities"]
                self.assertEqual(result["classification"], expected)
                self.assertAlmostEqual(sum(probabilities.values()), 1.0, places=3)
                self.assertEqual(
                    max(probabilities, key=probabilities.get),
                    expected.lower(),
                )

    def test_inference_rejects_malformed_payloads(self):
        client = app.test_client()
        response = client.post("/predict", json={"email_text": "hello", "urls": "not-a-list"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("urls", response.get_json()["error"])
        self.assertIn(
            "valid base64",
            _validate_email_payload({
                "email_text": "",
                "sender_email": "",
                "attachments": [{"filename": "x.pdf", "content_base64": "!!!"}],
            }),
        )

    def test_reported_email_is_phishing_with_shap(self):
        result = _predict_email(EXACT_REPORTED_EMAIL, "PayPal Security <security-alert@paypa1-account-update.xyz>")
        self.assertEqual(result["classification"], "Phishing")
        self.assertGreaterEqual(result["probability"], 0.60)
        self.assertTrue(result["top_email_text_features"])
        self.assertTrue(result["top_url_features"])
        self.assertTrue(result["top_sender_features"])

    def test_legitimate_regression_set(self):
        for sender, subject, body in LEGITIMATE_EMAILS:
            with self.subTest(sender=sender):
                result = _predict_email(f"Subject: {subject}\n{body}", sender)
                self.assertNotEqual(result["classification"], "Phishing")

    def test_urgency_and_account_phishing_set(self):
        for sender, subject, body in PHISHING_EMAILS:
            with self.subTest(sender=sender):
                result = _predict_email(f"Subject: {subject}\n{body}", sender)
                self.assertEqual(result["classification"], "Phishing")


if __name__ == "__main__":
    unittest.main()
