"""Pytest configuration for the project root.

This file exists so that pytest puts the project root on sys.path, which makes
`import legacy_device`, `import edge_gateway` and `import cloud_service` work
from inside tests/ without installing the project as a package. Removing it
breaks collection with ModuleNotFoundError.
"""
