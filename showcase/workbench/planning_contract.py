"""The model edits prose slots, never native package identity or structure."""

import copy

from showcase.live_budget import require

VERSION = "delivery-package-prose/2"


def prose_slots(example):
    return {
        "section_updates": [
            {"section_id": f"section_{i}", "summary": section["summary"]}
            for i, section in enumerate(example["candidate"]["sections"])
        ],
        "risk_summary": example["candidate"]["risk_summary"],
    }


def assemble_package(example, output):
    require(
        isinstance(output, dict) and set(output) == {"section_updates", "risk_summary"},
        "package_prose_fields_invalid",
    )
    updates = output["section_updates"]
    expected = prose_slots(example)["section_updates"]
    require(
        isinstance(updates, list) and len(updates) == len(expected),
        "package_prose_count_invalid",
    )
    require(
        isinstance(output["risk_summary"], str)
        and 20 <= len(output["risk_summary"]) <= 2000,
        "package_risk_text_invalid",
    )
    result = copy.deepcopy(example)
    for index, (update, slot) in enumerate(zip(updates, expected)):
        require(
            isinstance(update, dict)
            and set(update) == {"section_id", "summary"}
            and update["section_id"] == slot["section_id"],
            "package_prose_slot_invalid",
        )
        require(
            isinstance(update["summary"], str) and 20 <= len(update["summary"]) <= 1400,
            "package_prose_summary_invalid",
        )
        result["candidate"]["sections"][index]["summary"] = update["summary"]
    result["candidate"]["risk_summary"] = output["risk_summary"]
    return result
