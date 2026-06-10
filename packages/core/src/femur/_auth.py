import os
from typing import Optional

from dotenv import load_dotenv


def load_credentials(env_file: Optional[str] = None) -> dict:
    """Load CrowdStrike API credentials from a .env file and/or environment variables.

    Resolution order (highest to lowest priority):
      1. Existing environment variables
      2. Values from env_file (or .env in the working directory if not specified)
      3. Built-in defaults (BASE_URL defaults to "US1")

    Args:
        env_file: Path to a .env file. Defaults to .env in the current directory.

    Returns:
        dict with keys ``client_id``, ``client_secret``, ``base_url``.
        Suitable for unpacking directly into a falconpy service class constructor.

    Example::

        from femur import load_credentials, get_all_hosts

        creds = load_credentials("talon1.env")
        hosts = get_all_hosts(creds)
    """
    load_dotenv(dotenv_path=env_file, override=False)
    return {
        "client_id": os.environ.get("CLIENT_ID", ""),
        "client_secret": os.environ.get("CLIENT_SECRET", ""),
        "base_url": os.environ.get("BASE_URL", "US1"),
    }
