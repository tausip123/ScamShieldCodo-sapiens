import unittest
from io import BytesIO
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

from api import app
from engine import investigate_image


class ImageInvestigationTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @patch("engine.extract_text_from_image")
    def test_investigate_image_successful_pipeline(self, mock_ocr):
        mock_ocr.return_value = "Dear customer, your SBI account will be blocked today. Update KYC: http://sbi-kyc-update.xyz/login"
        dummy_image = b"dummy_png_bytes"

        res = investigate_image(dummy_image, mime_type="image/png", force_heuristic=True)
        self.assertEqual(res["verdict"], "SCAM")
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertIn("sbi-kyc-update.xyz", str(res["why"]))
        self.assertIn("Update KYC", res["extracted_text"])

    @patch("engine.extract_text_from_image", side_effect=RuntimeError("Vision quota exceeded"))
    def test_investigate_image_graceful_error_handling(self, mock_ocr):
        dummy_image = b"dummy_png_bytes"
        res = investigate_image(dummy_image, mime_type="image/png")
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual(res["engine"], "image_error_fallback")
        self.assertIn("AI vision", str(res["why"]))

    @patch("api.investigate_image")
    def test_api_image_endpoint(self, mock_inv_img):
        mock_inv_img.return_value = {
            "verdict": "SCAM",
            "risk_score": 90,
            "why": ["Deceptive domain detected in screenshot"],
            "actions": ["Do not click link"],
            "entities": {"urls": ["http://sbi-fake.xyz"], "upi_ids": [], "phone_numbers": [], "amounts": [], "urgency_words": []},
            "complaint": "Sample complaint",
            "engine": "heuristic_rule_engine",
            "fallback_reason": None,
            "raw_text": "VERDICT: SCAM",
            "extracted_text": "Extracted SMS text from screenshot"
        }

        file_content = BytesIO(b"fake_image_file_content")
        response = self.client.post(
            "/api/v1/investigate/image",
            files={"file": ("screenshot.png", file_content, "image/png")},
            data={"optional_text": "Received on WhatsApp"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["verdict"], "SCAM")
        self.assertEqual(data["extracted_text"], "Extracted SMS text from screenshot")


if __name__ == "__main__":
    unittest.main()
