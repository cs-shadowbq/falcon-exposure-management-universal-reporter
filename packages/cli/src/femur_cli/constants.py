"""CLI defaults and shared constants for femur."""

# Default output settings
DEFAULT_OUTPUT_FILE = "femur_inventory.json"
DEFAULT_INDENT = 2
DEFAULT_OUTPUT_FORMAT = "json"

# Fetch settings
DEFAULT_VULN_WORKERS = 1
MAX_CONCURRENT_FETCHES = 4

# Dataset identifiers
DATASET_APPLICATIONS = "applications"
DATASET_VULNERABILITIES = "vulnerabilities"
DATASET_ASSESSMENTS = "assessments"
DATASET_HOST_MAP = "host_map"

CORE_DATASETS = (DATASET_APPLICATIONS, DATASET_VULNERABILITIES, DATASET_ASSESSMENTS)
ALL_DATASETS = (*CORE_DATASETS, DATASET_HOST_MAP)

# Display labels for Rich progress output
DATASET_LABELS = {
    DATASET_APPLICATIONS: "Applications",
    DATASET_VULNERABILITIES: "Vulnerabilities",
    DATASET_ASSESSMENTS: "Assessments",
    DATASET_HOST_MAP: "Host Map",
}
