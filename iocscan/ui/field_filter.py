"""Dot-path field-selector for JSON-shaped payloads.

Path grammar:
- Segments separated by `.`.
- `*` is a wildcard that matches every element of a list.
- Other segments match dict keys verbatim. A literal `"0"` does not
  index into a list — only `*` traverses lists.

apply_filter(payload, include, exclude) returns a NEW dict:
- If `include` is non-empty, only paths matching any include are kept.
- Then any path matching `exclude` is removed.
- Missing paths are silently ignored.
- The input payload is never mutated.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any


def _walk_include(src: Any, path: list[str], dest: Any) -> None:
    """Copy fields from `src` into `dest`, guided by `path`.

    `dest` is a container (dict or list) that the caller has already
    shaped to mirror the structure of `src` up to this point.
    """
    if not path:
        return
    head, *rest = path
    if head == "*":
        if not isinstance(src, list) or not isinstance(dest, list):
            return
        # Pad `dest` so we have an entry per source index.
        for idx, item in enumerate(src):
            if idx >= len(dest):
                # Use {} as the per-index placeholder for dicts, [] for lists,
                # or None for scalar leaves — picked based on remaining path.
                if not rest:
                    dest.append(None)
                elif rest[0] == "*":
                    dest.append([])
                else:
                    dest.append({})
            if not rest:
                dest[idx] = deepcopy(item)
            else:
                _walk_include(item, rest, dest[idx])
        return
    # Literal key path. Only dicts have keys.
    if not isinstance(src, dict) or head not in src or not isinstance(dest, dict):
        return
    value = src[head]
    if not rest:
        dest[head] = deepcopy(value)
        return
    # If the next step is into a list but the path doesn't use `*`, the path
    # is invalid — bail without creating a stray placeholder container.
    if isinstance(value, list) and rest[0] != "*":
        return
    if rest[0] == "*":
        if head not in dest or not isinstance(dest[head], list):
            dest[head] = []
    else:
        if head not in dest or not isinstance(dest[head], dict):
            dest[head] = {}
    _walk_include(value, rest, dest[head])


def _walk_exclude(node: Any, path: list[str]) -> None:
    if not path or node is None:
        return
    head, *rest = path
    if head == "*":
        if isinstance(node, list):
            for item in node:
                _walk_exclude(item, rest)
        return
    if not isinstance(node, dict) or head not in node:
        return
    if not rest:
        del node[head]
        return
    _walk_exclude(node[head], rest)


def apply_filter(
    payload: dict, include: list[str], exclude: list[str]
) -> dict:
    if not include and not exclude:
        return payload
    if include:
        result: dict = {}
        for path in include:
            segments = [s for s in path.split(".") if s]
            if not segments:
                continue
            _walk_include(payload, segments, result)
    else:
        # Deepcopy so callers' input dict is never mutated by exclude.
        result = deepcopy(payload)
    for path in exclude:
        segments = [s for s in path.split(".") if s]
        if not segments:
            continue
        _walk_exclude(result, segments)
    return result
