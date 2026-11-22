"""Qt-free helpers for reading/toggling Pwnagotchi plugin state in config.toml.

Pwnagotchi configs normally use *dotted* keys at the document root::

    main.plugins.grid.enabled = true      # comment allowed

but ``[main.plugins.grid]`` tables are also valid, so both are supported.
All edits are textual (not a TOML round-trip) so comments and layout survive.
"""
from __future__ import annotations

import re

_NAME = r"[a-zA-Z0-9_\-]+"
_TAIL = r"(\s*(?:#.*)?)$"  # optional trailing comment


def parse_plugins_from_ls(output: str) -> list[str]:
    names = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("total"):
            continue
        if line.endswith(".py"):
            base = line[:-3]
            if base and base != "__init__":
                names.append(base)
    return sorted(set(names))


def _table_span(text: str, plugin: str):
    """Return (body_start, body_end) of a ``[main.plugins.<plugin>]`` table."""
    m = re.search(
        rf"^[ \t]*\[main\.plugins\.{re.escape(plugin)}\][ \t]*(?:#.*)?$",
        text, flags=re.MULTILINE)
    if not m:
        return None
    start = m.end()
    nxt = re.search(r"^[ \t]*\[", text[start:], flags=re.MULTILINE)
    end = start + nxt.start() if nxt else len(text)
    return start, end


def extract_enabled_from_toml(toml_text: str) -> dict[str, bool]:
    """Plugin -> enabled. A real parse is authoritative (handles every TOML
    style); the regex scanner is the fallback for configs that do not parse."""
    try:
        plugins = _loads(toml_text).get("main", {}).get("plugins", {})
        return {n: v["enabled"] for n, v in plugins.items()
                if isinstance(v, dict) and isinstance(v.get("enabled"), bool)}
    except Exception:  # noqa: BLE001
        return _extract_enabled_regex(toml_text)


def _extract_enabled_regex(toml_text: str) -> dict[str, bool]:
    enabled: dict[str, bool] = {}

    for m in re.finditer(
        rf"^[ \t]*main\.plugins\.({_NAME})\.enabled[ \t]*=[ \t]*(true|false)[ \t]*(?:#.*)?$",
        toml_text,
        flags=re.MULTILINE,
    ):
        enabled[m.group(1)] = (m.group(2) == "true")

    for m in re.finditer(
        rf"^[ \t]*\[main\.plugins\.({_NAME})\][ \t]*(?:#.*)?$",
        toml_text,
        flags=re.MULTILINE,
    ):
        name = m.group(1)
        span = _table_span(toml_text, name)
        if not span:
            continue
        body = toml_text[span[0]:span[1]]
        m2 = re.search(r"^[ \t]*enabled[ \t]*=[ \t]*(true|false)[ \t]*(?:#.*)?$",
                       body, flags=re.MULTILINE)
        if m2:
            enabled[name] = (m2.group(1) == "true")

    return enabled


def _loads(text: str):
    try:
        import tomllib
    except ModuleNotFoundError:  # py3.10
        import tomli as tomllib
    return tomllib.loads(text)


def _tomlkit_toggle(toml_text: str, plugin: str, enabled: bool):
    """Format-preserving toggle of an EXISTING ``enabled`` key; None if the
    result cannot be proven correct (caller falls back to the text editor)."""
    try:
        import tomlkit
        before = _loads(toml_text)
        doc = tomlkit.parse(toml_text)
        doc["main"]["plugins"][plugin]["enabled"] = bool(enabled)
        out = tomlkit.dumps(doc)
        after = _loads(out)
        # Only that one value may differ.
        expect = _loads(toml_text)
        expect["main"]["plugins"][plugin]["enabled"] = bool(enabled)
        if after != expect or out == toml_text and before != after:
            return None
        return out
    except Exception:  # noqa: BLE001 - any parse/shape problem => fallback
        return None


def _exists_in_doc(toml_text: str, plugin: str) -> bool:
    """True if the plugin has an ``enabled`` key in ANY TOML style (dotted,
    table, inline table) — decided by a real parse, not by regexes."""
    try:
        return "enabled" in _loads(toml_text)["main"]["plugins"][plugin]
    except Exception:  # noqa: BLE001
        return plugin in extract_enabled_from_toml(toml_text)


def set_plugin_enabled_in_toml(toml_text: str, plugin: str, enabled: bool) -> str:
    if _exists_in_doc(toml_text, plugin):
        out = _tomlkit_toggle(toml_text, plugin, enabled)
        if out is not None:
            return out
    return _set_plugin_enabled_text(toml_text, plugin, enabled)


def _set_plugin_enabled_text(toml_text: str, plugin: str, enabled: bool) -> str:
    val = "true" if enabled else "false"

    dotted = re.compile(
        rf"^([ \t]*main\.plugins\.{re.escape(plugin)}\.enabled[ \t]*=[ \t]*)(true|false)"
        rf"([ \t]*(?:#.*)?)$",
        flags=re.MULTILINE,
    )
    if dotted.search(toml_text):
        return dotted.sub(rf"\g<1>{val}\g<3>", toml_text)

    span = _table_span(toml_text, plugin)
    if span:
        start, end = span
        block = toml_text[start:end]
        en_re = re.compile(
            r"^([ \t]*enabled[ \t]*=[ \t]*)(true|false)([ \t]*(?:#.*)?)$",
            flags=re.MULTILINE)
        if en_re.search(block):
            block2 = en_re.sub(rf"\g<1>{val}\g<3>", block)
        else:
            stripped = block.rstrip()
            tail = block[len(stripped):]
            block2 = stripped + f"\nenabled = {val}" + (tail if tail else "\n")
            if not block2.endswith("\n"):
                block2 += "\n"
        return toml_text[:start] + block2 + toml_text[end:]

    # Not mentioned anywhere: add a root-level dotted key. It must go BEFORE
    # the first [table] header, otherwise it would silently belong to
    # whatever table happens to be last in the file. (A new [main.plugins.x]
    # table could also clash with dotted keys defined elsewhere => invalid TOML.)
    line = f"main.plugins.{plugin}.enabled = {val}\n"
    hdr = re.search(r"^[ \t]*\[", toml_text, flags=re.MULTILINE)
    if hdr:
        return toml_text[:hdr.start()] + line + "\n" + toml_text[hdr.start():]
    base = toml_text if toml_text.endswith("\n") or not toml_text else toml_text + "\n"
    return base + line
