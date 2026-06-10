"""IAVM (Information Assurance Vulnerability Management) CVE cross-reference.

Parses the DISA IAVM notice-to-CVE cross-reference XML and builds an in-memory
lookup index mapping CVE IDs to their associated IAVM notice metadata.

The XML schema is::

    <cvexref xmlns="http://iavm.csd.disa.mil/schemas/IavmNoticeCveXref/1.0">
        <notice id="1012" number="2024-T-0012" severity="CAT I" title="...">
            <cvelist>
                <cve>CVE-2024-0741</cve>
                ...
            </cvelist>
        </notice>
    </cvexref>

Typical usage::

    from femur_pipeline.iavm import parse_iavm_xml

    index = parse_iavm_xml("path/to/iavm-cve-xref.xml")
    # index["CVE-2024-0741"] == [{"iavm_number": "2024-T-0012", ...}]
"""

import defusedxml.ElementTree as ET
from typing import Dict, IO, List, Union

# Namespace used in the DISA IAVM CVE cross-reference XML.
IAVM_NS = "http://iavm.csd.disa.mil/schemas/IavmNoticeCveXref/1.0"

# Convenience type alias for the lookup index.
IavmIndex = Dict[str, List[Dict[str, str]]]


def parse_iavm_xml(source: Union[str, IO]) -> IavmIndex:
    """Parse IAVM CVE cross-reference XML into a CVE -> notices lookup.

    Parameters
    ----------
    source : str or file-like
        Path to the XML file, or an open file object.

    Returns
    -------
    dict
        Mapping of CVE ID strings to lists of notice metadata dicts.
        Each notice dict contains ``iavm_number``, ``iavm_severity``,
        and ``iavm_title``.
    """
    tree = ET.parse(source)
    root = tree.getroot()
    index: IavmIndex = {}

    for notice in root.iter(f"{{{IAVM_NS}}}notice"):
        meta = {
            "iavm_number": notice.get("number", ""),
            "iavm_severity": notice.get("severity", ""),
            "iavm_title": notice.get("title", ""),
        }
        for cve_el in notice.iter(f"{{{IAVM_NS}}}cve"):
            cve_id = (cve_el.text or "").strip()
            if cve_id:
                index.setdefault(cve_id, []).append(meta)

    return index


def parse_iavm_metadata(source: Union[str, IO]) -> Dict[str, str]:
    """Extract metadata from IAVM CVE cross-reference XML.

    Parameters
    ----------
    source : str or file-like
        Path to the XML file, or an open file object.

    Returns
    -------
    dict
        Metadata dict with keys like ``date_generated``.
    """
    tree = ET.parse(source)
    root = tree.getroot()
    meta: Dict[str, str] = {}

    metadata_el = root.find(f"{{{IAVM_NS}}}metaData")
    if metadata_el is not None:
        date_el = metadata_el.find(f"{{{IAVM_NS}}}dateGenerated")
        if date_el is not None and date_el.text:
            meta["date_generated"] = date_el.text.strip()

    return meta


def lookup_iavm(index: IavmIndex, cve_id: str) -> List[Dict[str, str]]:
    """Look up IAVM notices for a given CVE ID.

    Parameters
    ----------
    index : dict
        The lookup index returned by :func:`parse_iavm_xml`.
    cve_id : str
        A CVE identifier (e.g. ``"CVE-2024-0741"``).

    Returns
    -------
    list
        List of matching notice metadata dicts, or empty list if no match.
    """
    return index.get(cve_id, [])
