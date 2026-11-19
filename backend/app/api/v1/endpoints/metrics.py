"""Read-only endpoint for the latest offline model evaluation."""

import json
import logging
from fastapi import APIRouter, HTTPException, status

from ml.evaluation.evaluate import METRICS_PATH

router = APIRouter(prefix="/metrics", tags=["Metrics"])
logger = logging.getLogger(__name__)

REQUIRED_METRIC_FIELDS = {
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "confusion_matrix",
    "test_set_size",
    "model_version",
    "timestamp",
}


@router.get("")
def get_model_metrics():
    """Return metrics computed by the offline evaluator; never infer or fabricate them."""
    try:
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        logger.error("Evaluation metrics are missing at %s", METRICS_PATH)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Evaluation metrics are unavailable. Run the model evaluation first.",
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        logger.exception("Could not read evaluation metrics from %s", METRICS_PATH)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Evaluation metrics could not be loaded.",
        ) from exc

    if not isinstance(metrics, dict) or not REQUIRED_METRIC_FIELDS.issubset(metrics):
        logger.error("Evaluation metrics at %s do not match the required schema", METRICS_PATH)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Evaluation metrics are invalid. Run the model evaluation again.",
        )
    return metrics
