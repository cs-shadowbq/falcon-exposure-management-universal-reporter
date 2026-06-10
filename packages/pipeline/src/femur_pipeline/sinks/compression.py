"""Shared compression utilities for output sinks.

Provides scalable file-level and directory-level zip compression,
parallelized via thread pools.
"""

import concurrent.futures
import os
import shutil
import zipfile
from typing import List, Optional


def zip_individual_files(directory: str) -> None:
    """Zip each file in a directory individually, removing originals.

    Each file ``foo.jsonl`` becomes ``foo.jsonl.zip`` containing the
    original file at the archive root.  The original is deleted after
    successful compression.

    Parameters
    ----------
    directory : str
        Path to the directory whose files should be zipped.
    """
    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        zip_path = fpath + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(fpath, arcname=fname)
        os.remove(fpath)


def zip_directory(directory: str) -> None:
    """Zip an entire directory into a single archive, removing the directory.

    The archive is named ``{directory}.zip`` and preserves the directory
    name as a prefix in the archive paths.

    Parameters
    ----------
    directory : str
        Path to the directory to archive.
    """
    zip_path = directory + ".zip"
    dir_name = os.path.basename(directory)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in os.listdir(directory):
            fpath = os.path.join(directory, fname)
            if os.path.isfile(fpath):
                zf.write(fpath, arcname=os.path.join(dir_name, fname))
    shutil.rmtree(directory)


def compress_output_files(
    directory: str,
    exclude: Optional[List[str]] = None,
) -> None:
    """Zip each file in a flat output directory, excluding named files.

    Useful for non-bucketed output (JSONL/XML flat directories).
    Excludes files by name (e.g. ``manifest.json``, ``manifest.xml``)
    so the manifest remains discoverable without unzipping.

    Parameters
    ----------
    directory : str
        Output directory containing files to compress.
    exclude : list of str, optional
        Filenames to skip (default: ``["manifest.json", "manifest.xml"]``).
    """
    if exclude is None:
        exclude = ["manifest.json", "manifest.xml"]
    exclude_set = set(exclude)

    for fname in os.listdir(directory):
        if fname in exclude_set:
            continue
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        zip_path = fpath + ".zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(fpath, arcname=fname)
        os.remove(fpath)


def compress_directories_parallel(
    directories: List[str],
    mode: str = "individual",
    max_workers: int = 8,
) -> None:
    """Compress multiple directories in parallel.

    Parameters
    ----------
    directories : list of str
        Directories to process.
    mode : str
        ``"individual"`` — zip each file within each directory.
        ``"directory"`` — zip each directory into a single archive.
    max_workers : int
        Maximum parallel threads (default 8).
    """
    if not directories:
        return
    workers = min(max_workers, len(directories))
    fn = zip_directory if mode == "directory" else zip_individual_files
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        pool.map(fn, directories)
