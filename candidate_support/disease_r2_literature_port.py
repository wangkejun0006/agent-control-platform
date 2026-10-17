"""Read-only Literature Tool port over one frozen public corpus revision."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

CORPUS_REF = "dataset://public/disease-r2/fictional-stationery-literature/0.1.0"
CORPUS_REVISION = (
    "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30"
)
_INJECTION = re.compile(
    r"(?:ignore (?:all |the )?(?:previous|prior) instructions|system prompt|"
    r"developer message|reveal (?:the )?(?:secret|credential)|"
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|/Users/|/Volumes/|file://|smb://)",
    re.IGNORECASE,
)


class DiseaseR2LiteratureError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class FrozenPublicLiteraturePort:
    def __init__(self, corpus_path: Path | str) -> None:
        path = Path(corpus_path)
        if not path.is_file() or path.is_symlink():
            raise DiseaseR2LiteratureError("r2_corpus_source_invalid")
        source = path.read_bytes()
        if "sha256:" + hashlib.sha256(source).hexdigest() != CORPUS_REVISION:
            raise DiseaseR2LiteratureError("r2_corpus_revision_drift")
        try:
            records = [
                json.loads(line, object_pairs_hook=_unique_object)
                for line in source.decode().splitlines()
                if line
            ]
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DiseaseR2LiteratureError("r2_corpus_invalid") from error
        if len(records) != 8:
            raise DiseaseR2LiteratureError("r2_corpus_record_count_drift")
        self._records: dict[str, dict[str, Any]] = {}
        for record in records:
            if (
                not isinstance(record, dict)
                or not str(record.get("record_ref", "")).startswith(
                    "artifact://public/pubmed/"
                )
                or not str(record.get("citation_id", "")).startswith("PMID:")
                or record["record_ref"] in self._records
                or "sha256:"
                + hashlib.sha256(str(record.get("abstract", "")).encode()).hexdigest()
                != record.get("abstract_digest")
            ):
                raise DiseaseR2LiteratureError("r2_corpus_record_invalid")
            self._records[record["record_ref"]] = record

    def search(self, query_id: str, query_text: str, *, maximum: int = 4) -> dict[str, Any]:
        if (
            not isinstance(query_id, str)
            or not query_id.startswith("query_")
            or not isinstance(query_text, str)
            or len(query_text) > 512
            or _INJECTION.search(query_text)
            or "stationery" not in query_text.lower()
            or not 1 <= maximum <= 4
        ):
            raise DiseaseR2LiteratureError("r2_literature_query_invalid")
        terms = {
            term
            for term in re.findall(r"[a-z][a-z-]{3,}", query_text.lower())
            if term not in {"with", "from", "that", "this"}
        }
        ranked = []
        for record in self._records.values():
            title = str(record.get("title", "")).lower()
            if "stationery" not in title and "catalog issue" not in title:
                continue
            haystack = " ".join(
                [record["title"], record["abstract"], *record["mesh_terms"]]
            ).lower()
            score = sum(term in haystack for term in terms)
            if score:
                ranked.append((score, record["citation_id"], record))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        projection = [
            {
                "record_ref": record["record_ref"],
                "citation_id": record["citation_id"],
                "title": record["title"],
                "doi": record["doi"],
                "publication_date": record["publication_date"],
                "mesh_terms": record["mesh_terms"],
                "abstract_digest": record["abstract_digest"],
                "score": score,
            }
            for score, _, record in ranked[:maximum]
        ]
        return {
            "schema_version": "orbit.literature-public-corpus-search-response/0.1",
            "request_id": f"litsearch_r2_{query_id}",
            "corpus_ref": CORPUS_REF,
            "corpus_revision": CORPUS_REVISION,
            "query_id": query_id,
            "records": projection,
            "result_digest": _digest(projection),
            "replayed": False,
            "data_classification": "public",
        }

    def fetch(self, record_refs: list[str]) -> dict[str, Any]:
        if (
            not isinstance(record_refs, list)
            or not 1 <= len(record_refs) <= 8
            or len(record_refs) != len(set(record_refs))
        ):
            raise DiseaseR2LiteratureError("r2_literature_fetch_invalid")
        try:
            records = [deepcopy(self._records[ref]) for ref in record_refs]
        except KeyError as error:
            raise DiseaseR2LiteratureError("r2_literature_record_not_authorized") from error
        for record in records:
            record.pop("publication_date_precision", None)
        return {
            "schema_version": "orbit.literature-public-corpus-fetch-response/0.1",
            "request_id": "litfetch_r2_execution_001",
            "corpus_ref": CORPUS_REF,
            "corpus_revision": CORPUS_REVISION,
            "records": records,
            "result_digest": _digest(records),
            "replayed": False,
            "data_classification": "public",
        }


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise DiseaseR2LiteratureError("r2_corpus_duplicate_json_key")
        value[key] = item
    return value

