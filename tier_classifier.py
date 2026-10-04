"""
Root tier_classifier module forwarding to lambdas/tier_classifier.py.
"""
from lambdas.tier_classifier import classify_tier

__all__ = ["classify_tier"]
