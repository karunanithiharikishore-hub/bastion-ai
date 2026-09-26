"""Ingestion: read raw log files/dirs and yield normalized Events."""
from .loader import ingest_path, ingest_paths, detect_source

__all__ = ["ingest_path", "ingest_paths", "detect_source"]
