import json
import re
from datetime import datetime
from docx import Document


def load_placeholder_map(key_path):
    if not key_path.exists():
        return {}

    with key_path.open("r", encoding="utf-8") as key_file:
        saved_entries = json.load(key_file)

    loaded = {}
    for entry in saved_entries:
        category = entry["category"]
        value = entry["original_value"]
        lowered = value.casefold()

        if category == "PERSON" and re.search(
            r"\b(county|office|group|services|school|district|university|"
            r"college|corporation|company|llc|inc\.?|corp\.?)\b",
            lowered,
        ):
            category = "LOCATION" if "county" in lowered else "ORGANIZATION"

        placeholder = entry["placeholder"]
        if placeholder in loaded.values() and category in {"ORGANIZATION", "LOCATION"}:
            prefix = get_initials(value)
            number = 1
            candidate = f"{prefix}{number}"
            while candidate in loaded.values():
                number += 1
                candidate = f"{prefix}{number}"
            placeholder = candidate

        loaded[(category, value)] = placeholder

    return loaded


def save_placeholder_map(key_path, placeholder_map):
    saved_entries = [
        {
            "category": category,
            "original_value": original_value,
            "placeholder": placeholder,
        }
        for (category, original_value), placeholder in placeholder_map.items()
    ]

    with key_path.open("w", encoding="utf-8") as key_file:
        json.dump(saved_entries, key_file, indent=2)


def get_initials(value):
    words = re.findall(r"[A-Za-z]+", value)
    return "".join(word[0].upper() for word in words[:2]) or "UNKNOWN"


def get_email_initials(email):
    return get_initials(email.split("@", 1)[0])


def normalize_value(category, value):
    if category == "PHONE":
        return re.sub(r"\D", "", value)
    if category == "DOB":
        cleaned = re.sub(
            r"(?i)\b(date of birth|dob|born)\b\s*[:\-]?\s*",
            "",
            value,
        ).strip()
        for fmt in (
            "%m/%d/%Y", "%m-%d-%Y", "%m/%d/%y", "%m-%d-%y",
            "%B %d, %Y", "%B %d %Y", "%d %B %Y", "%d %b %Y",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(cleaned, fmt).date().isoformat()
            except ValueError:
                pass
        return re.sub(r"\s+", " ", cleaned.casefold())
    return re.sub(r"\s+", " ", value.casefold()).strip()


def get_person_alias_by_initials(initials, placeholder_map):
    matches = [
        alias
        for (category, _), alias in placeholder_map.items()
        if category == "PERSON" and alias.startswith(initials)
    ]
    return matches[0] if len(matches) == 1 else None


def get_placeholder(category, value, placeholder_map):
    normalized = normalize_value(category, value)
    for (stored_category, stored_value), alias in placeholder_map.items():
        if (
            stored_category == category
            and normalize_value(category, stored_value) == normalized
        ):
            placeholder_map[(category, value)] = alias
            return alias

    key = (category, value)

    if category == "PERSON":
        normalized = value.casefold()
        for (stored_category, stored_value), alias in placeholder_map.items():
            if stored_category == "PERSON" and stored_value.casefold() == normalized:
                placeholder_map[key] = alias
                return alias

        surname = re.sub(r"(?i)^(mr|mrs|ms|miss|dr)\.\s+", "", value).split()[-1]
        surname_matches = [
            alias
            for (stored_category, stored_value), alias in placeholder_map.items()
            if stored_category == "PERSON"
            and stored_value.casefold().split()[-1] == surname.casefold()
        ]
        if len(surname_matches) == 1:
            placeholder_map[key] = surname_matches[0]
            return surname_matches[0]

    if category == "EMAIL":
        person_alias = get_person_alias_by_initials(
            get_email_initials(value), placeholder_map
        )
        placeholder = (
            f"{person_alias}@company.gov"
            if person_alias
            else f"{get_email_initials(value)}1@example.invalid"
        )
    elif category == "PERSON":
        initials = get_initials(value)
        aliases = {
            alias
            for (stored_category, _), alias in placeholder_map.items()
            if alias.startswith(initials)
        }
        placeholder = f"{initials}{len(aliases) + 1}"
    elif category == "ORGANIZATION":
        initials = get_initials(value)
        aliases = {
            alias
            for (stored_category, _), alias in placeholder_map.items()
            if stored_category == category and alias.startswith(initials)
        }
        count = 1
        placeholder = f"{initials}{count}"
        while placeholder in placeholder_map.values():
            count += 1
            placeholder = f"{initials}{count}"
    else:
        count = sum(1 for stored_category, _ in placeholder_map if stored_category == category)
        placeholder = f"{category}_{count + 1}"

    placeholder_map[key] = placeholder
    return placeholder


def save_redaction_key(key_path, placeholder_map):
    document = Document()
    document.add_heading("Redaction Key", level=1)
    document.add_paragraph(
        "This document contains the original sensitive information "
        "that was replaced during redaction. Keep it private."
    )
    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    table.rows[0].cells[0].text = "Placeholder"
    table.rows[0].cells[1].text = "Original Value"

    for (category, original_value), placeholder in placeholder_map.items():
        cells = table.add_row().cells
        cells[0].text = placeholder
        cells[1].text = original_value

    document.save(key_path)
