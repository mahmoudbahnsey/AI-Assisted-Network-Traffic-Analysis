"""
IDS/IPS system for detecting and blocking network attacks
"""

from .detector import AttackDetector
from .blocker import AttackBlocker

__all__ = ['AttackDetector', 'AttackBlocker']
