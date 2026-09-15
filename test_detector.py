"""
test_detector.py — Unit tests for the deterministic parts of detector.py
--------------------------------------------------------------------------
Covers the pieces that don't depend on Ollama or the trained ML model:
scoring/fusion math, label thresholds, rule-based pattern matching, and
LLM output sanitization. Run with:

    python3 -m unittest test_detector -v

No pytest dependency required — this uses the standard library so it
runs in any environment that already has the project's requirements.
"""

import unittest

import detector


class TestClampAndUtil(unittest.TestCase):
    def test_clamp_int_within_range(self):
        self.assertEqual(detector.clamp_int(50, 0, 100), 50)

    def test_clamp_int_clips_high(self):
        self.assertEqual(detector.clamp_int(150, 0, 100), 100)

    def test_clamp_int_clips_low(self):
        self.assertEqual(detector.clamp_int(-10, 0, 100), 0)

    def test_clamp_int_non_numeric_uses_default(self):
        self.assertEqual(detector.clamp_int("not a number", 0, 100, default=7), 7)

    def test_uniq_keep_order(self):
        self.assertEqual(
            detector.uniq_keep_order(["a", "b", "a", "c", "b"]),
            ["a", "b", "c"],
        )


class TestScoring(unittest.TestCase):
    def test_score_to_label_boundaries(self):
        self.assertEqual(detector.score_to_label(0), "SAFE")
        self.assertEqual(detector.score_to_label(39), "SAFE")
        self.assertEqual(detector.score_to_label(40), "SUSPICIOUS")
        self.assertEqual(detector.score_to_label(69), "SUSPICIOUS")
        self.assertEqual(detector.score_to_label(70), "PHISHING")
        self.assertEqual(detector.score_to_label(100), "PHISHING")

    def test_combine_rule_ml_uses_tuned_alpha(self):
        # RULE_ML_ALPHA is the empirically tuned weight (see tune_weights.py);
        # this pins the formula, not the constant, so a future retune doesn't
        # silently change behavior without a test catching it.
        rule_risk, ml_risk = 20, 80
        expected = round(detector.RULE_ML_ALPHA * rule_risk + (1 - detector.RULE_ML_ALPHA) * ml_risk)
        self.assertEqual(detector.combine_rule_ml(rule_risk, ml_risk), expected)

    def test_compute_final_score_with_llm(self):
        expected = round(detector.LLM_BETA * 50 + (1 - detector.LLM_BETA) * 90)
        self.assertEqual(detector.compute_final_score(50, 90, use_llm=True), expected)

    def test_compute_final_score_without_llm_ignores_llm_score(self):
        # When the LLM didn't run, its score must have zero influence —
        # this is the exact bug that was fixed: a fabricated fallback
        # score used to get blended in even when unavailable.
        self.assertEqual(detector.compute_final_score(50, 999, use_llm=False), 50)

    def test_final_score_always_clamped(self):
        self.assertLessEqual(detector.compute_final_score(100, 100, use_llm=True), 100)
        self.assertGreaterEqual(detector.compute_final_score(0, 0, use_llm=True), 0)


class TestRuleBasedURL(unittest.TestCase):
    def test_flags_ip_address_url(self):
        score, reasons, flags = detector.detect_suspicious_link("http://192.168.1.5/login")
        self.assertIn("suspicious_link", flags)
        self.assertGreater(score, 0)

    def test_flags_url_shortener(self):
        _, _, flags = detector.detect_suspicious_link("https://bit.ly/3xample")
        self.assertIn("suspicious_link", flags)

    def test_flags_credential_theft_keywords(self):
        _, reasons, flags = detector.detect_suspicious_link("https://paypal-login-verify.xyz/account")
        self.assertIn("credential_request", flags)
        self.assertTrue(any(reasons))

    def test_clean_url_scores_low(self):
        score, _, flags = detector.detect_suspicious_link("https://www.wikipedia.org")
        self.assertEqual(score, 0)
        self.assertEqual(flags, [])

    def test_only_controlled_flags_returned(self):
        _, _, flags = detector.detect_suspicious_link("http://192.168.1.5/login-verify-secure")
        self.assertTrue(set(flags).issubset(detector.CONTROLLED_FLAGS_SET))


class TestRuleBasedMessage(unittest.TestCase):
    def test_flags_otp_request(self):
        _, reasons, flags = detector.detect_message_patterns("Please send your OTP code now.")
        self.assertIn("credential_request", flags)
        self.assertIn("urgency", flags)

    def test_flags_remote_access_request(self):
        _, _, flags = detector.detect_message_patterns("Please install AnyDesk so we can fix it.")
        self.assertIn("remote_access", flags)

    def test_benign_message_scores_zero(self):
        score, reasons, flags = detector.detect_message_patterns("Hi, are you around for lunch tomorrow?")
        self.assertEqual(score, 0)
        self.assertEqual(flags, [])

    def test_known_limitation_free_is_a_false_positive_trigger(self):
        # Documents a real, current limitation rather than hiding it: the
        # reward_bait rule matches the bare word "free" with no surrounding
        # context, so an innocuous "free for lunch" scores as reward bait.
        # This is a known false-positive source in the keyword-only rule
        # layer (see showcase notes / future work: the ML+LLM layers are
        # what keep the final hybrid score correct in practice, since
        # neither of them fires on this input).
        score, reasons, flags = detector.detect_message_patterns("Are you free for lunch tomorrow?")
        self.assertEqual(score, 1)
        self.assertIn("reward_bait", flags)

    def test_empty_string_is_safe(self):
        score, reasons, flags = detector.detect_message_patterns("")
        self.assertEqual(score, 0)
        self.assertEqual(flags, [])


class TestNormalizeLLMOutput(unittest.TestCase):
    def test_clamps_risk_score(self):
        out = detector.normalize_llm_output({"risk_score": 500, "label": "PHISHING"})
        self.assertEqual(out["risk_score"], 100)

    def test_invalid_label_derived_from_score(self):
        out = detector.normalize_llm_output({"risk_score": 85, "label": "not-a-real-label"})
        self.assertEqual(out["label"], "PHISHING")

    def test_filters_uncontrolled_red_flags(self):
        out = detector.normalize_llm_output({
            "risk_score": 50, "label": "SUSPICIOUS",
            "red_flags": ["urgency", "made_up_flag_the_model_invented"],
        })
        self.assertEqual(out["red_flags"], ["urgency"])

    def test_handles_missing_fields_gracefully(self):
        out = detector.normalize_llm_output({})
        self.assertEqual(out["label"], "SAFE")
        self.assertEqual(out["risk_score"], 0)
        self.assertEqual(out["reasons"], [])


class TestInputTypeDetection(unittest.TestCase):
    def test_detects_https_url(self):
        self.assertTrue(detector.looks_like_url("https://example.com/verify"))

    def test_detects_bare_domain(self):
        self.assertTrue(detector.looks_like_url("example.com/verify"))

    def test_plain_message_is_not_a_url(self):
        self.assertFalse(detector.looks_like_url("Hi, are you free tomorrow?"))


if __name__ == "__main__":
    unittest.main()
