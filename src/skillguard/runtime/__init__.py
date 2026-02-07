"""
Runtime defense module.

Integrates AgentShepherd and Spider-Sense for inference-time protection.
"""

from skillguard.runtime.shepherd_integration import RuntimeDefender
from skillguard.runtime.intrinsic_risk_sensing import IntrinsicRiskSensor

__all__ = ["RuntimeDefender", "IntrinsicRiskSensor"]
