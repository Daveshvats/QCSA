"""Interval Type-2 Fuzzy Inference System (IT2-FIS) membership functions.

IT2 fuzzy sets represent *uncertainty about uncertainty* — exactly what we have
when multiple layers disagree. Instead of a single membership value μ(x), an
IT2 set gives an interval [μ_lower(x), μ_upper(x)] — the "footprint of uncertainty".

This is the application of Muhuri's research domain (interval type-2 fuzzy
systems) to the bug-finding aggregation problem.

Reference: Mendel, J.M. (2001) "Uncertain Rule-Based Fuzzy Logic Systems";
Muhuri's work on IT2 fuzzy for real-time systems applies the same math.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Tuple
import math


@dataclass
class IT2Membership:
    """An interval type-2 membership value: [lower, upper] in [0, 1].

    The gap (upper - lower) is the *footprint of uncertainty*. When we have
    high confidence in a signal, lower ≈ upper. When we're uncertain,
    lower << upper.
    """
    lower: float
    upper: float

    def __post_init__(self):
        self.lower = max(0.0, min(1.0, self.lower))
        self.upper = max(self.lower, min(1.0, self.upper))

    @property
    def midpoint(self) -> float:
        return (self.lower + self.upper) / 2

    @property
    def uncertainty(self) -> float:
        """Footprint of uncertainty — 0 means certain, 1 means totally uncertain."""
        return self.upper - self.lower

    def __and__(self, other: "IT2Membership") -> "IT2Membership":
        """t-norm (min) for IT2 — intersection."""
        return IT2Membership(min(self.lower, other.lower), min(self.upper, other.upper))

    def __or__(self, other: "IT2Membership") -> "IT2Membership":
        """t-conorm (max) for IT2 — union."""
        return IT2Membership(max(self.lower, other.lower), max(self.upper, other.upper))

    def __repr__(self):
        return f"IT2[{self.lower:.2f}, {self.upper:.2f}]"


# --- Triangular/trapezoidal IT2 membership function generators ------------

def it2_triangular(a: float, b: float, c: float,
                   footprint: float = 0.1) -> Callable[[float], IT2Membership]:
    """IT2 triangular membership function.

    `footprint` is the spread between upper and lower MFs — represents the
    uncertainty in the membership function definition itself.

    Standard Zadeh MF: μ(x) = max(0, min((x-a)/(b-a), (c-x)/(c-b)))
    Upper MF: μ_upper(x) = μ(x) * (1 - footprint/2) ... no, simpler:
    We just shift b by ±footprint/2 to get upper and lower MFs.
    """
    b_lower = b - footprint / 2
    b_upper = b + footprint / 2

    def _tri(x, b):
        if x < a or x > c:
            return 0.0
        if x == b:
            return 1.0
        if x < b:
            return (x - a) / (b - a) if b > a else (1.0 if x >= a else 0.0)
        return (c - x) / (c - b) if c > b else (1.0 if x <= c else 0.0)

    def f(x: float) -> IT2Membership:
        u_lower = _tri(x, b_upper)  # narrower triangle → lower membership
        u_upper = _tri(x, b_lower)  # wider triangle → higher membership
        return IT2Membership(u_lower, u_upper)
    return f


def it2_trapezoidal(a: float, b: float, c: float, d: float,
                    footprint: float = 0.1) -> Callable[[float], IT2Membership]:
    """IT2 trapezoidal MF — for linguistic terms like 'medium'."""
    b_lower, b_upper = b - footprint / 2, b + footprint / 2
    c_lower, c_upper = c - footprint / 2, c + footprint / 2

    def _trap(x, b, c):
        if x < a or x > d:
            return 0.0
        if b <= x <= c:
            return 1.0
        if x < b:
            return (x - a) / (b - a) if b > a else 1.0
        return (d - x) / (d - c) if d > c else 1.0

    def f(x: float) -> IT2Membership:
        # lower MF: narrower trapezoid
        u_lower = _trap(x, b_upper, c_lower)
        # upper MF: wider trapezoid
        u_upper = _trap(x, b_lower, c_upper)
        return IT2Membership(u_lower, u_upper)
    return f


# --- Linguistic variable definitions for the FIS ---------------------------

class SeverityMF:
    """Type-2 membership functions for the severity input (0..1 score)."""
    def __init__(self):
        self.low = it2_trapezoidal(0.0, 0.0, 0.2, 0.35, footprint=0.08)
        self.medium = it2_trapezoidal(0.25, 0.4, 0.55, 0.7, footprint=0.08)
        self.high = it2_trapezoidal(0.6, 0.75, 0.85, 0.92, footprint=0.08)
        self.critical = it2_trapezoidal(0.88, 0.95, 1.0, 1.0, footprint=0.05)

    def evaluate(self, x: float) -> dict:
        return {
            "low": self.low(x), "medium": self.medium(x),
            "high": self.high(x), "critical": self.critical(x),
        }


class ConfidenceMF:
    """Type-2 MF for confidence (0..1) — uncertainty about uncertainty is the
    entire point of using IT2 here."""
    def __init__(self):
        # higher footprint because confidence is inherently fuzzy
        self.uncertain = it2_trapezoidal(0.0, 0.0, 0.3, 0.5, footprint=0.15)
        self.moderate = it2_trapezoidal(0.35, 0.5, 0.7, 0.85, footprint=0.15)
        self.certain = it2_trapezoidal(0.75, 0.9, 1.0, 1.0, footprint=0.08)

    def evaluate(self, x: float) -> dict:
        return {
            "uncertain": self.uncertain(x),
            "moderate": self.moderate(x),
            "certain": self.certain(x),
        }


class BlastRadiusMF:
    """Type-2 MF for blast radius (encoded as 0=function, 0.5=module, 1=system)."""
    def __init__(self):
        self.function = it2_triangular(0.0, 0.0, 0.3, footprint=0.08)
        self.module = it2_triangular(0.2, 0.5, 0.8, footprint=0.10)
        self.system = it2_triangular(0.7, 1.0, 1.0, footprint=0.08)

    def evaluate(self, x: float) -> dict:
        return {
            "function": self.function(x),
            "module": self.module(x),
            "system": self.system(x),
        }


class ExploitabilityMF:
    """Type-2 MF for exploitability (0..1)."""
    def __init__(self):
        self.none = it2_trapezoidal(0.0, 0.0, 0.15, 0.3, footprint=0.08)
        self.indirect = it2_trapezoidal(0.25, 0.4, 0.6, 0.75, footprint=0.10)
        self.direct = it2_trapezoidal(0.7, 0.85, 1.0, 1.0, footprint=0.08)

    def evaluate(self, x: float) -> dict:
        return {
            "none": self.none(x),
            "indirect": self.indirect(x),
            "direct": self.direct(x),
        }


class SourceReliabilityMF:
    """Type-2 MF for the source layer's historical reliability (precision/recall)."""
    def __init__(self):
        self.unproven = it2_trapezoidal(0.0, 0.0, 0.3, 0.45, footprint=0.12)
        self.reliable = it2_trapezoidal(0.4, 0.55, 0.75, 0.85, footprint=0.10)
        self.trusted = it2_trapezoidal(0.8, 0.9, 1.0, 1.0, footprint=0.05)

    def evaluate(self, x: float) -> dict:
        return {
            "unproven": self.unproven(x),
            "reliable": self.reliable(x),
            "trusted": self.trusted(x),
        }


# --- Output MFs (decision) -------------------------------------------------

class DecisionMF:
    """Output linguistic variable: decision = {pass, warn, block}.

    Encoded as 0=pass, 0.5=warn, 1=block for centroid defuzzification.
    """
    def __init__(self):
        self.pass_ = it2_triangular(0.0, 0.0, 0.35, footprint=0.05)
        self.warn = it2_triangular(0.25, 0.5, 0.75, footprint=0.08)
        self.block = it2_triangular(0.65, 1.0, 1.0, footprint=0.05)

    def evaluate(self, x: float) -> dict:
        return {"pass": self.pass_(x), "warn": self.warn(x), "block": self.block(x)}


# helper: encode blast radius enum to 0..1
def encode_blast_radius(br_str: str) -> float:
    return {"function": 0.0, "module": 0.5, "system": 1.0}.get(br_str, 0.0)
