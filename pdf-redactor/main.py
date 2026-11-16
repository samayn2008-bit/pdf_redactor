## Warning filter
import warnings

warnings.filterwarnings(
    "ignore",
    message="The `fitz` API is deprecated.*",
    category=FutureWarning
)

##re for regex, and spacy for NER models
import argparse
from pathlib import Path
from pdf2docx import Converter
import re
import spacy
from docx import Document
import tempfile
import pymupdf
import shlex
import sys
import json
from redaction import mapping as mapping_utils

parser = argparse.ArgumentParser(description="Convert a PDF to DOCX and mask sensitive information")

##load spacCy's small English model
nlp = spacy.load("en_core_web_sm")

placeholder_map = {}

def load_placeholder_map(key_path):
    if not key_path.exists():
        return {}

    with key_path.open("r", encoding="utf-8") as key_file:
        saved_entries = json.load(key_file)

    return {
        (entry["category"], entry["original_value"]): entry["placeholder"]
        for entry in saved_entries
    }

def save_placeholder_map(key_path):
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


def save_redaction_key(key_path):
    key_document = Document();

    key_document.add_heading("Redaction Key", level=1)

    key_document.add_paragraph(
        "This document contains the original sensitive information "
        "that was replaced during redaction. Keep it private."
    )

    table = key_document.add_table(rows=1, cols=2)
    table.style = "Table Grid"

    header = table.rows[0].cells
    header[0].text = "Placeholder"
    header[1].text = "Original Value"

    for (category, original_value), placeholder in placeholder_map.items():
        row = table.add_row().cells
        row[0].text = placeholder
        row[1].text = original_value

    key_document.save(key_path)


def get_initials(value):
    words = re.findall(r"[A-Za-z]+", value)

    if not words:
        return "UNKNOWN"

    return "".join(word[0].upper() for word in words[:2])

def get_email_initials(email):
    local_part = email.split("@", 1)[0]

    words = re.findall(r"[A-Za-z]+", local_part)

    if not words:
        return "UNKNOWN"

    return "".join(word[0].upper() for word in words[:2])


def get_person_alias_by_initials(initials):
    matches = [
        alias
        for (stored_category, _), alias in placeholder_map.items()
        if stored_category == "PERSON"
        and alias.startswith(initials)
    ]

    if len(matches) == 1:
        return matches[0]

    return None


def get_placeholder(category, value):
    key = (category, value)

    if key in placeholder_map:
        return placeholder_map[key]

    if category == "PERSON":
        normalized_value = value.casefold()

        for (stored_category, stored_value), alias in placeholder_map.items():
            if (
                stored_category == "PERSON"
                and stored_value.casefold() == normalized_value
            ):
                placeholder_map[key] = alias
                return alias

    if category == "ORGANIZATION":
        initials = get_initials(value)

        existing_aliases = {
            alias
            for (stored_category, _), alias in placeholder_map.items()
            if stored_category == "ORGANIZATION"
            and alias.startswith(initials)
        }

        count = len(existing_aliases) + 1
        placeholder = f"{initials}{count}"

        placeholder_map[key] = placeholder
        return placeholder

    if category == "DOB":
        count = sum(
            1
            for stored_category, _ in placeholder_map
            if stored_category == "DOB"
        )

        placeholder = f"DOB_{count + 1}"
        placeholder_map[key] = placeholder
        return placeholder

    if category == "ADDRESS":
        count = sum(
            1
            for stored_category, _ in placeholder_map
            if stored_category == "ADDRESS"
        )

        placeholder = f"ADDRESS_{count + 1}"
        placeholder_map[key] = placeholder
        return placeholder

    if category == "LOCATION":
        count = sum(
            1
            for stored_category, _ in placeholder_map
            if stored_category == "LOCATION"
        )

        placeholder = f"LOCATION_{count + 1}"
        placeholder_map[key] = placeholder
        return placeholder

    if category == "EMAIL":
        initials = get_email_initials(value)
        person_alias = get_person_alias_by_initials(initials)

        if person_alias:
            placeholder = f"{person_alias}@company.gov"
        else:
            existing_email_aliases = {
                alias.split("@", 1)[0]
                for (stored_category, _), alias in placeholder_map.items()
                if stored_category == "EMAIL"
            }

            count = 1
            candidate = f"{initials}{count}"

            while candidate in existing_email_aliases:
                count += 1
                candidate = f"{initials}{count}"

            placeholder = f"{candidate}@example.invalid"

        placeholder_map[key] = placeholder
        return placeholder

    if category == "PERSON":
        initials = get_initials(value)

        existing_aliases = {
            alias 
            for (stored_category, _), alias in placeholder_map.items()
            if stored_category == "PERSON" and alias.startswith(initials)
        }

        count = len(existing_aliases) + 1
        placeholder = f"{initials}{count}"
    else:
        count = sum(
            1 for stored_category, _ in placeholder_map
            if stored_category == category
        )

        placeholder = f"{category}_{count+1}"

    placeholder_map[key] = placeholder

    return placeholder


# Mapping implementations live in redaction.mapping. Keep the local names
# as compatibility aliases for callers that import them from main.
load_placeholder_map = mapping_utils.load_placeholder_map
save_placeholder_map = lambda key_path: mapping_utils.save_placeholder_map(
    key_path,
    placeholder_map,
)
save_redaction_key = lambda key_path: mapping_utils.save_redaction_key(
    key_path,
    placeholder_map,
)
get_placeholder = lambda category, value: mapping_utils.get_placeholder(
    category,
    value,
    placeholder_map,
)


def get_open_command(file_path):
    if sys.platform == "darwin":
        return f"open {shlex.quote(str(file_path))}"

    elif sys.platform.startswith("linux"):
        return f"xdg-open {shlex.quote(str(file_path))}"

    elif sys.platform == "win32":
        return f'start "" "{str(file_path)}"'

    else:
        return str(file_path)

def mask_paragraph(paragraph):
    runs = paragraph.runs

    if not runs:
        return

    original_texts = [run.text for run in runs]
    full_text = "".join(original_texts)

    spans = find_sensitive_spans(full_text)

    if not spans:
        return

    # Determine each run's position in original paragraph
    position = 0

    # Construct each run's new text without shifting positions
    for i, run in enumerate(runs):
        original = original_texts[i]
        
        run_start = position
        run_end = position + len(original)
        position = run_end

        ## Find sensitive spans overlapping this run
        relevant = [
            (start, end, placeholder)
            for start, end, placeholder in spans
            if start < run_end and end > run_start
        ]

        ## Work right to left to avoid shifting indices
        for start, end, placeholder in reversed(relevant):
            local_start = max(0, start - run_start)
            local_end = min(len(original_texts[i]), end - run_start)

            # Insert placeholder only where the match begins
            replacement = (
                placeholder if run_start <= start < run_end else ""
            )

            original = (
                original[:local_start] + replacement + original[local_end:]
            )

        if relevant:
            run.text = original

def valid_person_name(name):
    #Name must have 2-4 name-like words.
    words = name.split()
    excluded_names = {
            "email",
            "name",
            "phone",
            "number",
            "address",
            "contact",
            "ssn",
            "contact information",
            "case number",
            "reference number"
    }

    if name.casefold() in excluded_names:
        return False

    if not 2 <= len(words) <= 4:
        return False

    # Exclude obvious non-name structures
    if any(char.isdigit() for char in name):
        return False
    
    # Names with numbers, email addresses, or field separators
    if "@" in name or " - " in name or "|" in name or ";" in name:
        return False

    if re.search(r"(?i)\b(and|or|the|of|with|unless)\b", name):
        return False

    if re.search(r"(?i)[’']s\b", name):
        return False

    # Reject legal case titles
    if re.search(r"\b(v\.?|vs\.?|versus)\b", name, re.I):
        return False

    return True


def find_sensitive_spans(text):
    patterns = {
        "EMAIL": r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE": r"(?<!\d)(?:\+?1[\s.-]*)?(?:\(\d{3}\)|\d{3})[\s.-]*\d{3}[\s.-]*\d{4}(?!\d)",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "CASE_NUMBER": r"\bFX[-/]CIV[-/]\d{4}[-/]\d{4}\b",
        "IDENTIFIER": r"\b[A-Z]{2,4}-[A-Z]{2,4}-\d{2,6}\b",
        "URL": r"https?://[^\s<>]+",
    }

    legal_entity_pattern = re.compile(
        r"\b[A-Z][A-Za-z&.'-]*(?:\s+[A-Z][A-Za-z&.'-]*){0,6}"
        r"\s+(?:Inc\.?|LLC|Ltd\.?|Limited|Corporation|Corp\.?|"
        r"Company|Co\.?|PLC|LP|LLP|P\.C\.|"
        r"High School|Middle School|Elementary School|School|District|"
        r"University|College)\b"
    )

    labeled_dob_patterns = [
        r"(?i)\b(?:date of birth|dob|born)\s*[:\-]?\s*"
        r"(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-]\d{2,4}\b",
        r"(?i)\b(?:date of birth|dob|born)\s*[:\-]?\s*"
        r"(?:January|February|March|April|May|June|July|August|September|"
        r"October|November|December)\s+\d{1,2},\s+\d{4}\b",
    ]

    date_patterns = [
        r"(?i)\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-]\d{2,4}\b",
        r"(?i)\b(?:January|February|March|April|May|June|July|August|September|"
        r"October|November|December)\s+\d{1,2},?\s+\d{4}\b",
        r"\b\d{4}-\d{2}-\d{2}\b",
    ]

    address_pattern = re.compile(
        r"\b\d{1,6}\s+[^,\n]+(?:,\s*[^,\n]+){1,3},\s*[A-Z]{2}\s+"
        r"\d{5}(?:-\d{4})?\b"
    )

    structured_spans = []


    # 1. Detect emails, phones, and SSNs first
    for category, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            start, end = match.span()

            if not any(start < e and e > s for s, e, _ in structured_spans):
                structured_spans.append((start, end, category))

    for pattern in labeled_dob_patterns:
        for match in re.finditer(pattern, text):
            start, end = match.span()

            if not any(
                start < existing_end and end > existing_start
                for existing_start, existing_end, _ in structured_spans
            ):
                structured_spans.append((start, end, "DOB"))

    if re.search(r"(?i)\b(date of birth|dob|born)\b", text):
        for pattern in date_patterns:
            for match in re.finditer(pattern, text):
                start, end = match.span()
                if not any(
                    start < existing_end and end > existing_start
                    for existing_start, existing_end, _ in structured_spans
                ):
                    structured_spans.append((start, end, "DOB"))

    for match in address_pattern.finditer(text):
        start, end = match.span()

        if not any(
            start < existing_end and end > existing_start
            for existing_start, existing_end, _ in structured_spans
        ):
            structured_spans.append((start, end, "ADDRESS"))

    for match in legal_entity_pattern.finditer(text):
        start, end = match.span()

        if not any(
            start < existing_end and end > existing_start
            for existing_start, existing_end, _ in structured_spans
        ):
            structured_spans.append(
                (start, end, "ORGANIZATION")
            )


    # 2. Prepare text for spaCy without changing offsets
    chars = list(text.replace("\u200b", " "))

    for start, end, _ in structured_spans:
        for i in range(start, end):
            if chars[i] != "\n":
                chars[i] = " "

    analysis_text = "".join(chars)

    # 3. Detect potential names
    doc = nlp(analysis_text)
    person_spans = []
    
    #Detect plaintiff name in a case caption like (Name v. Corporation)
    caption_match = re.search(
        r"(?im)^\s*([A-Z][A-Z]+(?:\s+[A-Z][A-Z]+){1,3})\s+v\.?\s+",
        text,
    )

    if caption_match:
        person_spans.append(
            (
                caption_match.start(1),
                caption_match.end(1),
                "PERSON",
            )
        )

    for entity in doc.ents:

        if entity.label_ not in {"PERSON", "ORG", "GPE", "LOC", "FAC"}:
            continue

        entity_text = analysis_text[entity.start_char:entity.end_char]   

        line_start = text.rfind("\n", 0, entity.start_char) + 1
        line_end = text.find("\n", entity.end_char)
        if line_end == -1:
            line_end = len(text)
        source_line = text[line_start:line_end].strip()

        if entity_text.strip().isupper() and " v." not in source_line.lower():
            continue

        if entity_text.casefold().strip() == "social security":
            continue

        entity_tokens = list(entity)
        entity_has_legal_suffix = bool(
            re.search(
                r"\b(LLC|Inc\.?|Ltd\.?|Limited|Corporation|Corp\.?|"
                r"District|County|PLC|LP|LLP|P\.C\.)\b",
                entity_text,
                re.I,
            )
        )

        if entity.label_ != "PERSON":
            if len(entity_tokens) < 2 and not entity_has_legal_suffix:
                continue

            if re.match(
                r"(?i)^(plaintiff|defendant|counsel|attorney|clerk)\b",
                entity_text.strip(),
            ):
                continue
        elif len(entity_tokens) < 2:
            continue

        if entity.label_ == "PERSON":
            category = "PERSON"
        elif entity.label_ == "ORG":
            category = "ORGANIZATION"    
        else:
            category = "LOCATION"

        #Split long predictions at field separators
        separators = list(re.finditer(r"\s+-\s+|[;|\n]", entity_text))

        boundaries = [0]
        for separator in separators:
            boundaries.extend([
                separator.start(),
                separator.end()
            ])
        boundaries.append(len(entity_text))

        # Each pair represents a candidate section
        for i in range(0, len(boundaries) - 1, 2):
            local_start = boundaries[i]
            local_end = boundaries[i + 1]

            chunk = entity_text[local_start:local_end]
            candidate = chunk.strip()

            if category == "PERSON" and not valid_person_name(candidate):
                continue

            # Translate back to original text positions
            leading_space = len(chunk) - len(chunk.lstrip())

            start = (
                entity.start_char
                + local_start
                + leading_space
            )
            end = start + len(candidate)

            # Avoid overlap with structured identifiers
            if any(
                start < e and end > s
                for s, e, _ in structured_spans
            ):
                continue

            person_spans.append((start, end, "PERSON"))

    # Find known person names that spaCy missed
    known_person_names = [
        original_value
        for (category, original_value) in placeholder_map
        if category == "PERSON"
    ]

    for original_value in known_person_names:
        for match in re.finditer(
            rf"(?<!\w){re.escape(original_value)}(?!\w)",
            text,
            flags=re.IGNORECASE,
        ):
            person_spans.append(
                (match.start(), match.end(), "PERSON")
            )

    # 4. Combine matches and keep the longest non-overlapping span
    candidates = structured_spans + person_spans
    candidates.sort(key=lambda span: (-(span[1] - span[0]), span[0]))

    accepted = []
    for start, end, category in candidates:
        if any(
            start < existing_end and end > existing_start
            for existing_start, existing_end, _ in accepted
        ):
            continue

        accepted.append((start, end, category))

    # Restore the original document order
    accepted.sort(key=lambda span: span[0])

    # 5. Assign placeholders to the initial matches
    numbered_spans = []

    for start, end, category in accepted:
        original_value = text[start:end]
        placeholder = get_placeholder(category, original_value)
        numbered_spans.append((start, end, placeholder))

    # 6. Search again using all person names discovered in the paragraph
    known_person_names = [
        original_value
        for (category, original_value) in placeholder_map
        if category == "PERSON"
    ]

    for original_value in known_person_names:
        for match in re.finditer(
            rf"(?<!\w){re.escape(original_value)}(?!\w)",
            text,
            flags=re.IGNORECASE,
        ):
            start, end = match.span()

            if any(
                start < existing_end and end > existing_start
                for existing_start, existing_end, _ in numbered_spans
            ):
                continue

            placeholder = get_placeholder(
                "PERSON",
                text[start:end],
            )

            numbered_spans.append((start, end, placeholder))

    numbered_spans.sort(key=lambda span: span[0])
    
    return numbered_spans


#Account for containers like table/header/footer
def mask_container(container):
    for paragraph in container.paragraphs:
        mask_paragraph(paragraph)
        repair_spacing(paragraph)
    for table in container.tables:
        for row in table.rows:
            for cell in row.cells:
                mask_container(cell)


#Fix spacing
def repair_spacing(paragraph):
    runs = paragraph.runs

    #Record each character and the run it belongs to
    chars = [
        (char, i)
        for i, run in enumerate(runs)
        for char in run.text
    ]

    updated = ["" for _ in runs]
    pos = 0

    while pos < len(chars):
        char, run_index = chars[pos]

        if char != "\u200b":
            updated[run_index] += char
            pos += 1
            continue
    

        end = pos
        while end < len(chars) and chars[end][0] == "\u200b":
            end += 1

        left = chars[pos - 1][0] if pos else ""
        right = chars[end][0] if end < len(chars) else ""

        #Decide whether to insert a real space
        if (left and right and not left.isspace() and not right.isspace()
            and right not in ".,;:!?)]}" and left not in "({["
        ):
            updated[run_index] += " "

        pos = end

    #Update existing runs to preserve formatting
    for run, text in zip(runs, updated):
        if run.text != text:
            run.text = text


# Allow user to upload multiples files
input_group = parser.add_mutually_exclusive_group(required=True)

input_group.add_argument(
    "-p",
    "--pdf",
    help = "Path to one PDF file"
)

input_group.add_argument(
    "-i",
    "--input",
    help="Path to a folder containing PDF files"
)

parser.add_argument(
    "-o",
    "--output",
    help="Folder where anonymized files should be saved"
)

parser.add_argument(
    "--key",
    help="Path to the persistent redaction mapping JSON file"
)

def remove_pdf_links(pdf_path, temp_path):
    with pymupdf.open(str(pdf_path)) as pdf:
        for page in pdf:
            for link in page.get_links():
                page.delete_link(link)

        pdf.save(str(temp_path))

args = parser.parse_args();

if args.pdf:
    input_path = Path(args.pdf).expanduser().resolve()

    if not input_path.is_file():
        parser.error("The specified PDF file does not exist.")
    
    if input_path.suffix.lower() != ".pdf":
        parser.error("The specified file must be a PDF.")

    pdf_paths = [input_path]
    default_output_dir = input_path.parent

else:
    input_path = Path(args.input).expanduser().resolve()

    if not input_path.is_dir():
        parser.error("The specified input folder does not exist.")

    pdf_paths = sorted(
        path for path in input_path.iterdir()
        if path.is_file() and path.suffix.lower() == ".pdf"
    )

    if not pdf_paths:
        parser.error("The input folder contains no PDF files.")

    default_output_dir = input_path / "anonymized"

output_dir = (
    Path(args.output).expanduser().resolve()
    if args.output
    else default_output_dir
)

output_dir.mkdir(parents=True, exist_ok=True)

# Load previously assigned aliases before document scanning
if args.key:
    mapping_path = Path(args.key).expanduser().resolve()
else:
    mapping_path = output_dir / "case_mapping.json"

placeholder_map.update(mapping_utils.load_placeholder_map(mapping_path))

for pdf_path in pdf_paths:
    print("Processing:", pdf_path)

    output_path = output_dir / f"{pdf_path.stem}_redacted.docx"

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / "no_links.pdf"
        remove_pdf_links(pdf_path, temp_path)
        
        converter = Converter(str(temp_path))

        try:
            converter.convert(str(output_path))
        finally:
            converter.close()

    document = Document(output_path)

    mask_container(document)

    for section in document.sections:
        mask_container(section.header)
        mask_container(section.footer)

    document.save(output_path)

    redaction_key_path = (output_dir / f"{pdf_path.stem}_redacted_KEY.docx")
    
    mapping_utils.save_redaction_key(redaction_key_path, placeholder_map)
    mapping_utils.save_placeholder_map(mapping_path, placeholder_map)

    print("Created:", output_path)

print("Batch processing complete.")
print("Shared mapping key:", mapping_path)
