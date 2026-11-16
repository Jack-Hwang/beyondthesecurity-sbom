"""Vendored supporting modules for bts-sbom.

Every module here is vendored from the BTS platform (common/, misra_guard/
dataflow, sca_guard/) for the Apache-2.0 OSS release, with imports rewritten
to ``bts_sbom._internal.*`` and third-party dependencies (pydantic, requests,
license_expression, python-dotenv) replaced with stdlib equivalents. Each
file's header names its exact origin.
"""
