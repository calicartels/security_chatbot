import re
from typing import List, Dict, Any

import numpy as np

try:
    from sentence_transformers import CrossEncoder
except ImportError:  # pragma: no cover
    CrossEncoder = None


_token_pattern = re.compile(r"[^a-z0-9]+")
_version_pattern = re.compile(r"(\d+(?:[\.\-]\w+)+|\d+)")

_cross_encoder = None


def _tokenize(text: str) -> set:
    return set(filter(None, _token_pattern.split(text.lower())))


def _clean_component_name(name: str) -> str:
    # remove common suffixes that add noise
    return name.strip().strip("-")


def parse_infrastructure(infrastructure: str) -> List[Dict[str, Any]]:
    if not infrastructure:
        return []

    entries: List[Dict[str, Any]] = []
    segments = re.split(r"[\n,]+", infrastructure)

    for raw_segment in segments:
        segment = raw_segment.strip()
        if not segment:
            continue

        version_match = _version_pattern.search(segment)
        version = None
        name_part = segment

        if version_match:
            version = version_match.group(0)
            name_part = segment[: version_match.start()].strip()

        name_part = _clean_component_name(name_part)
        tokens = [
            token
            for token in _token_pattern.split(name_part.lower())
            if token and token not in {"lts", "server", "service", "version"}
        ]

        # fall back to using version as token when name missing (rare)
        if not tokens and version:
            tokens = [version]

        if not tokens:
            continue

        entries.append(
            {
                "raw": segment,
                "name": name_part,
                "tokens": tokens,
                "version": version.lower() if version else None,
            }
        )

    return entries


def _ensure_cross_encoder() -> CrossEncoder:
    global _cross_encoder
    if _cross_encoder is None:
        if CrossEncoder is None:
            raise ImportError("sentence_transformers is required for reranking")
        _cross_encoder = CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
    return _cross_encoder


def rerank_cves(query: str, infrastructure: str, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not cves:
        return []

    try:
        model = _ensure_cross_encoder()
    except Exception:  # pragma: no cover
        return [{"cve": cve, "rank_score": 0.0} for cve in cves]

    context = (query or "").strip()
    infra_text = (infrastructure or "").strip()
    left_text = f"{context} [SEP] {infra_text}".strip()

    pairs = [(left_text, f"{cve.get('id', '')} {cve.get('description', '')}") for cve in cves]
    scores = model.predict(pairs)

    order = np.argsort(scores)[::-1]
    ranked: List[Dict[str, Any]] = []
    for idx in order:
        ranked.append({"cve": cves[idx], "rank_score": float(scores[idx])})

    return ranked


def _collect_cve_texts(cve: Dict[str, Any]) -> List[str]:
    texts = []
    if cve.get("affected_products"):
        texts.extend(cve["affected_products"])
    if cve.get("description"):
        texts.append(cve["description"])
    if cve.get("id"):
        texts.append(cve["id"])
    return texts


def _match_component(component: Dict[str, Any], cve: Dict[str, Any]) -> Dict[str, Any]:
    texts = _collect_cve_texts(cve)
    component_tokens = set(component.get("tokens", []))
    version = component.get("version")
    name = (component.get("name") or "").lower()

    if not component_tokens:
        return {"score": 0, "name_match": False, "version_match": False, "matched_via": ""}

    name_match = False
    version_match = False
    matched_via = ""

    # First try structured CPE data
    for product in cve.get("affected_products", []) or []:
        entry = (product or "").lower()
        parts = entry.split(":")
        if len(parts) >= 6:
            vendor = parts[3]
            product_name = parts[4]
            product_version = parts[5]
            if name and (name == product_name or name == vendor or name in (vendor + " " + product_name)):
                name_match = True
                if version and version == product_version:
                    version_match = True
                    matched_via = "cpe"
            elif component_tokens & {vendor, product_name}:
                name_match = True
                if version and version == product_version:
                    version_match = True
                    matched_via = "cpe"

    # Fallback to free text only if version also present
    if not version_match:
        for text in texts:
            if not text:
                continue
            lowered = text.lower()
            tokens = _tokenize(lowered)
            if component_tokens.issubset(tokens):
                if version:
                    if version in lowered:
                        name_match = True
                        version_match = True
                        matched_via = matched_via or "text+version"
                else:
                    name_match = True
                    matched_via = matched_via or "text"

    score = 0
    if matched_via == "cpe":
        score = 2
    elif version_match and name_match:
        score = 2
    elif name_match and not version:
        score = 1

    return {
        "score": score,
        "name_match": name_match,
        "version_match": version_match,
        "matched_via": matched_via,
    }


def filter_and_rank_cves(
    query: str,
    infrastructure: str,
    cves: List[Dict[str, Any]],
    max_results: int = 5,
) -> List[Dict[str, Any]]:
    if not cves:
        return []

    components = parse_infrastructure(infrastructure)
    ranked = rerank_cves(query, infrastructure, cves)

    filtered: List[Dict[str, Any]] = []

    for item in ranked:
        cve = item["cve"]
        match_details = []
        total_score = 0

        if components:
            for component in components:
                result = _match_component(component, cve)
                if result["score"] > 0:
                    total_score += result["score"]
                    display = component["raw"]
                    if result["version_match"]:
                        display += " (version match)"
                    if result.get("matched_via"):
                        display += f" [{result['matched_via']}]"
                    match_details.append(display)

            if total_score == 0:
                continue
        else:
            match_details = []

        enriched = cve.copy()
        enriched["rank_score"] = item.get("rank_score", 0.0)
        enriched["match_score"] = total_score
        enriched["matched_components"] = match_details
        filtered.append(enriched)

        if len(filtered) >= max_results:
            break

    return filtered


