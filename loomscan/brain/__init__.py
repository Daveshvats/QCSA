"""Brain package — the IT2-FIS aggregation layer."""
from .it2_fis import IT2FIS, decision_from_score
from .membership import IT2Membership
from .rules import get_rules

# v4.9: Export BayesianSecondOpinion and ProjectTuner for orchestrator wiring
try:
    from .bayesian import BayesianSecondOpinion
except ImportError:
    BayesianSecondOpinion = None

try:
    from .project_tuner import ProjectTuner
except ImportError:
    ProjectTuner = None

__all__ = ["IT2FIS", "decision_from_score", "IT2Membership", "get_rules",
           "BayesianSecondOpinion", "ProjectTuner"]
