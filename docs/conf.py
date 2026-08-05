"""Sphinx configuration for the httpx-pki documentation.

The docs are authored in Markdown (MyST) but the package docstrings are
reStructuredText -- ``:class:``/``:meth:`` roles and ``::`` literal blocks --
so autodoc reads them natively and intersphinx turns the references to
``ssl``, ``cryptography`` and the standard library into working links.
"""

from __future__ import annotations

from httpx_pki import __version__

# -- Project ----------------------------------------------------------------

project = "httpx-pki"
author = "Carl Best"
copyright = "2026, Carl Best"  # noqa: A001

# Single-sourced from httpx_pki/__init__.py, the same place pyproject's
# dynamic version and the publish.yml tag check read it from.
release = __version__
version = ".".join(__version__.split(".")[:2])

# -- General ----------------------------------------------------------------

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_copybutton",
    "sphinx_design",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Warn about cross-references that do not resolve. Paired with
# fail_on_warning in .readthedocs.yaml, a typo'd :class: role fails the build
# instead of silently rendering as plain text.
nitpicky = True

# Everything below is unresolvable for a structural reason, not a typo. Keep
# these patterns tight: the point of nitpicky is that a genuine broken
# reference still fails the build.
nitpick_ignore_regex = [
    # Neither httpx2 nor httpx publishes an objects.inv, so their types cannot
    # be linked. Drop this entry (and add an intersphinx mapping) if that
    # changes -- these are the annotations users most want to follow.
    (r"py:.*", r"^httpx2?\..*"),
    # Private names that leak into public signatures: the _S TypeVar the
    # from_* classmethods return, _PKIMixin, _CertDetails, and friends. They
    # are intentionally undocumented.
    (r"py:.*", r"^_[A-Za-z_]*$"),
    (r"py:.*", r"^httpx_pki\..*\._[A-Za-z_]*$"),
    # cryptography annotates with the public x509.Certificate but the runtime
    # class lives in the Rust bindings, which its objects.inv does not carry.
    (r"py:.*", r"^cryptography\.hazmat\.bindings\._rust\..*"),
]

# -- MyST -------------------------------------------------------------------

myst_enable_extensions = [
    "colon_fence",      # ::: fences, so directives nest inside Markdown
    "deflist",          # definition lists for option/flag tables
    "attrs_inline",     # {.class} attributes on inline elements
    "substitution",     # |version|-style substitutions
    "linkify",          # bare URLs become links
]
myst_heading_anchors = 3  # #anchor links for h1-h3, so deep links survive
myst_substitutions = {"version": release}

# -- autodoc ----------------------------------------------------------------

autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autodoc_class_signature = "separated"
autodoc_preserve_defaults = True
autodoc_default_options = {
    "members": True,
    "show-inheritance": True,
}

# -- intersphinx ------------------------------------------------------------

# httpx2 is deliberately absent: it does not publish an objects.inv, so a
# mapping entry would only produce fetch warnings. httpx.* references are
# suppressed via nitpick_ignore above; add a mapping here if that changes.
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
}

# -- linkcheck --------------------------------------------------------------

# PyPI renders the per-file listing client-side, so linkcheck cannot see the
# #files anchor even though the link is good. Check the page, not the anchor.
linkcheck_anchors_ignore_for_url = [
    r"https://pypi\.org/project/httpx-pki/",
]

# -- HTML output ------------------------------------------------------------

html_theme = "furo"
html_static_path = ["_static"]
html_title = f"httpx-pki {release}"
html_theme_options = {
    "source_repository": "https://github.com/ccbest/httpx-pki/",
    "source_branch": "main",
    "source_directory": "docs/",
}
