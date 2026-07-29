import os
from typing import Optional

from dotenv import find_dotenv, dotenv_values, load_dotenv


_TRUTHY = {"1", "true", "yes", "on"}


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


def detect_workspace(env_file: Optional[str] = None) -> Optional[str]:
    """Return the workspace root directory, or ``None`` if not in a workspace.

    A "workspace" is a self-contained run directory (created by
    ``install.sh --type WORKSPACE``) holding ``.env``, ``data/`` and
    ``logs/``. It is marked by a truthy ``WORKSPACE`` entry in ``.env``
    (or the shell environment). The workspace root is defined as the
    directory *containing* the resolved ``.env`` — so running ``femur``
    from any subdirectory still resolves the correct ``data/``/``logs/``.

    Resolution order mirrors :func:`load_credentials`:
      1. A truthy ``WORKSPACE`` in the shell environment wins.
      2. Otherwise ``WORKSPACE`` read from ``env_file`` (or the nearest
         ``.env`` found by walking up from the current directory).

    Reads values with :func:`dotenv.dotenv_values`, which does **not**
    mutate ``os.environ`` — so calling this before :func:`load_credentials`
    cannot perturb the credential-priority logic.

    Args:
        env_file: Explicit path to a ``.env`` file. When ``None``, the
            nearest ``.env`` is discovered by walking up from the cwd.

    Returns:
        Absolute path to the workspace root, or ``None`` when ``WORKSPACE``
        is unset/falsy or no ``.env`` can be located.
    """
    # Resolve the .env path: explicit arg, else nearest ancestor.
    if env_file:
        resolved = os.path.abspath(os.path.expanduser(env_file))
        if not os.path.isfile(resolved):
            resolved = ""
    else:
        resolved = find_dotenv(usecwd=True)

    # Shell environment takes priority over the file value.
    env_flag = os.environ.get("WORKSPACE")
    if env_flag is not None:
        if env_flag.strip().lower() not in _TRUTHY:
            return None
        # Truthy in the shell: use the .env's dir if found, else cwd.
        if resolved:
            return os.path.dirname(os.path.abspath(resolved))
        return os.getcwd()

    # Fall back to the file value (without mutating os.environ).
    if not resolved:
        return None
    values = dotenv_values(resolved)
    file_flag = values.get("WORKSPACE")
    if file_flag is None or file_flag.strip().lower() not in _TRUTHY:
        return None
    return os.path.dirname(os.path.abspath(resolved))

