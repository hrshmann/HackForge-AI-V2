import logging
import os
import time
import warnings
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse

import joblib
import requests


LOGGER = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

REQUIRED_MODEL_SOURCES: Dict[str, str] = {
    "text_vectorizer.pkl": "https://huggingface.co/hrshmann/text_vectorizer.pkl/resolve/main/text_vectorizer.pkl",
    "url_threat_model.pkl": "https://huggingface.co/hrshmann/url_threat_model.pkl/resolve/main/url_threat_model.pkl",
    "text_threat_model.pkl": "https://huggingface.co/hrshmann/text_threat_model.pkl/resolve/main/text_threat_model.pkl",
    "web_vuln_ml_model.pkl": "https://huggingface.co/hrshmann/web_vuln_ml_model.pkl/resolve/main/web_vuln_ml_model.pkl",
}

HF_HTML_MARKERS = (
    b"<!doctype html",
    b"<html",
    b"Invalid username or password",
)


class ModelSetupError(RuntimeError):
    """Raised when required ML assets cannot be prepared."""


TREE_COMPAT_CLASS_NAMES = {
    "DecisionTreeClassifier",
    "DecisionTreeRegressor",
    "ExtraTreeClassifier",
    "ExtraTreeRegressor",
    "RandomForestClassifier",
    "RandomForestRegressor",
    "ExtraTreesClassifier",
    "ExtraTreesRegressor",
    "GradientBoostingClassifier",
    "GradientBoostingRegressor",
    "HistGradientBoostingClassifier",
    "HistGradientBoostingRegressor",
}


def _candidate_urls(source_url: str, filename: str) -> List[str]:
    """Return direct-download candidates for user-supplied Hugging Face links."""
    candidates: List[str] = []
    parsed = urlparse(source_url)

    if parsed.netloc == "huggingface.co" and "/resolve/" not in parsed.path:
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1]
            candidates.append(f"https://huggingface.co/{owner}/{repo}/resolve/main/{filename}")
            candidates.append(f"https://huggingface.co/{owner}/{repo}/resolve/main/{repo}")

    candidates.append(source_url)

    unique_candidates = []
    for candidate in candidates:
        if candidate not in unique_candidates:
            unique_candidates.append(candidate)
    return unique_candidates


def _is_non_empty_file(path: str) -> bool:
    return os.path.exists(path) and os.path.getsize(path) > 0


def _looks_like_html(path: str) -> bool:
    with open(path, "rb") as file:
        head = file.read(256).lstrip().lower()
    return any(head.startswith(marker.lower()) for marker in HF_HTML_MARKERS)


def _iter_children(value: Any) -> Iterable[Any]:
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return []

    if isinstance(value, dict):
        return value.values()

    if isinstance(value, (list, tuple, set)):
        return value

    if hasattr(value, "flat"):
        try:
            return list(value.flat)
        except TypeError:
            return []

    return []


def patch_sklearn_tree_compat(model: Any) -> Any:
    """Patch older sklearn tree pickles for newer runtimes expecting monotonic_cst."""
    visited: Set[int] = set()
    patched_counts: Dict[str, int] = {}

    def visit(obj: Any) -> None:
        if obj is None:
            return

        obj_id = id(obj)
        if obj_id in visited:
            return
        visited.add(obj_id)

        cls = obj.__class__
        cls_name = cls.__name__
        module_name = getattr(cls, "__module__", "")

        if module_name.startswith("sklearn.") and cls_name in TREE_COMPAT_CLASS_NAMES:
            if not hasattr(obj, "monotonic_cst"):
                setattr(obj, "monotonic_cst", None)
                patched_counts[cls_name] = patched_counts.get(cls_name, 0) + 1

        child_attrs = (
            "estimator_",
            "base_estimator_",
            "estimators_",
            "estimators",
            "steps",
            "named_steps",
            "transformer_list",
            "transformers_",
            "final_estimator_",
            "calibrated_classifiers_",
        )

        for attr in child_attrs:
            if hasattr(obj, attr):
                for child in _iter_children(getattr(obj, attr)):
                    visit(child)

    visit(model)
    for cls_name, count in patched_counts.items():
        LOGGER.info("Patched sklearn compatibility for %s %s object(s)", count, cls_name)
    return model


def load_joblib_model(path: str) -> Any:
    """Load a joblib model and normalize sklearn pickle compatibility."""
    try:
        from sklearn.exceptions import InconsistentVersionWarning
    except Exception:
        InconsistentVersionWarning = UserWarning

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InconsistentVersionWarning)
        model = joblib.load(path)
    return patch_sklearn_tree_compat(model)


def _download_stream(url: str, destination: str, timeout: int) -> None:
    temp_path = f"{destination}.part"
    if os.path.exists(temp_path):
        os.remove(temp_path)

    with requests.get(url, stream=True, timeout=timeout, allow_redirects=True) as response:
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" in content_type:
            raise ModelSetupError(f"URL returned HTML instead of a model file: {url}")

        total = int(response.headers.get("Content-Length", "0") or 0)
        downloaded = 0

        with open(temp_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                file.write(chunk)
                downloaded += len(chunk)
                if total:
                    percent = (downloaded / total) * 100
                    LOGGER.info("Downloading %s: %.1f%%", os.path.basename(destination), percent)

    if not _is_non_empty_file(temp_path):
        raise ModelSetupError(f"Downloaded file is empty: {url}")

    if _looks_like_html(temp_path):
        raise ModelSetupError(f"Downloaded content is HTML, not a pickle model: {url}")

    os.replace(temp_path, destination)


def _download_with_retries(
    filename: str,
    source_url: str,
    destination: str,
    retries: int,
    timeout: int,
) -> None:
    errors = []
    candidates = _candidate_urls(source_url, filename)

    for url in candidates:
        for attempt in range(1, retries + 1):
            try:
                LOGGER.info("Downloading %s from %s (attempt %s/%s)", filename, url, attempt, retries)
                _download_stream(url, destination, timeout)
                LOGGER.info("Model ready: %s", destination)
                return
            except Exception as exc:
                errors.append(f"{url} attempt {attempt}: {exc}")
                LOGGER.warning("Model download failed for %s: %s", filename, exc)
                if attempt < retries:
                    time.sleep(min(2 * attempt, 6))

    raise ModelSetupError(f"Could not download {filename}. Errors: {' | '.join(errors)}")


def ensure_nltk_resources(resources: Iterable[str] = ("punkt", "punkt_tab", "stopwords")) -> None:
    import nltk

    lookup_paths = {
        "punkt": "tokenizers/punkt",
        "punkt_tab": "tokenizers/punkt_tab",
        "stopwords": "corpora/stopwords",
    }

    for resource in resources:
        lookup_path = lookup_paths.get(resource, resource)
        try:
            nltk.data.find(lookup_path)
            LOGGER.info("NLTK resource already available: %s", resource)
        except LookupError:
            LOGGER.info("Downloading NLTK resource: %s", resource)
            try:
                downloaded = nltk.download(resource, quiet=True)
            except Exception as exc:
                if resource == "punkt_tab":
                    LOGGER.warning("Optional NLTK resource punkt_tab could not be downloaded: %s", exc)
                    continue
                raise ModelSetupError(f"Could not download NLTK resource {resource}: {exc}") from exc

            if not downloaded:
                if resource == "punkt_tab":
                    LOGGER.warning("Optional NLTK resource punkt_tab is not available")
                    continue
                raise ModelSetupError(f"Could not download NLTK resource {resource}")


def setup_models(retries: int = 3, timeout: int = 60) -> Dict[str, str]:
    """Prepare local ML models and NLTK resources for Streamlit/Render deployments."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    resolved_paths: Dict[str, str] = {}
    for filename, source_url in REQUIRED_MODEL_SOURCES.items():
        destination = os.path.join(MODELS_DIR, filename)
        if _is_non_empty_file(destination):
            LOGGER.info("Using cached model: %s", destination)
            resolved_paths[filename] = destination
            continue

        _download_with_retries(
            filename=filename,
            source_url=source_url,
            destination=destination,
            retries=retries,
            timeout=timeout,
        )
        resolved_paths[filename] = destination

    ensure_nltk_resources()
    return resolved_paths
