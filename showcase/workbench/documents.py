"""UTF-8 document intake and deterministic evidence retrieval; no network."""

import csv
import io
from pathlib import Path

from showcase.live_budget import digest, require, strict_json

MEDIA = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
}


def parse_document(filename, content):
    require(
        Path(filename).name == filename and Path(filename).suffix.lower() in MEDIA,
        "仅支持UTF-8的txt、md、csv、json；PDF/DOCX暂不解析",
    )
    require(0 < len(content) <= 256 * 1024, "资料须为1字节至256KiB")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError:
        require(False, "资料不是有效UTF-8文本")
    require("\x00" not in text, "资料包含不支持的二进制内容")
    suffix = Path(filename).suffix.lower()
    if suffix == ".json":
        strict_json(text)
    if suffix == ".csv":
        rows = list(csv.reader(io.StringIO(text)))
        require(
            bool(rows) and all(len(r) == len(rows[0]) for r in rows), "CSV列数不一致"
        )
    lines = text.splitlines()
    require(len(lines) <= 2000, "资料行数超限")
    chunks = [
        {"line": number, "text": line[:1600]}
        for number, line in enumerate(lines, 1)
        if line.strip()
    ]
    require(bool(chunks), "资料没有可解析内容")
    warnings = []
    if any(
        word in text for word in ("忽略审批", "泄露密钥", "绕过权限", "ignore previous")
    ):
        warnings.append("包含不可信指令；仅作为资料，不能改变工具、权限或审批规则")
    return {
        "media_type": MEDIA[suffix],
        "chunks": chunks,
        "warnings": warnings,
        "parse_status": "parsed",
        "content_digest": digest({"text": text}),
    }


def retrieve(documents, query, *, limit=8):
    terms = [t for t in query.replace("，", " ").replace("、", " ").split() if t]
    hits = []
    for doc in documents:
        for chunk in doc["chunks"]:
            score = sum(term in chunk["text"] for term in terms)
            if score:
                hits.append(
                    {
                        "artifact_ref": doc["artifact_ref"],
                        "filename": doc["filename"],
                        "version": doc["version"],
                        "digest": doc["content_digest"],
                        "line": chunk["line"],
                        "text": chunk["text"],
                        "score": score,
                    }
                )
    return sorted(hits, key=lambda h: (-h["score"], h["artifact_ref"], h["line"]))[
        :limit
    ]
