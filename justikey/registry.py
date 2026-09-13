"""Principal registries as privileged configuration.

The disclosure service decides whose approvals and whose proofs of presence
it will accept by reading two files on its own host. That the application
cannot write them is the point of stage 3 — but "the application cannot write
it" is not the same as "nobody can", and it says nothing at all about what
happens when someone *can*.

Two attacks the file alone does not resist, both available to an attacker who
reaches the service host or the path the file travels:

  REPLACEMENT   swap in a registry containing a key the attacker holds, and
                every subsequent approval verifies perfectly
  ROLLBACK      restore yesterday's copy, reinstating a key that was revoked
                this morning; nothing in a bare JSON file remembers that a
                newer version ever existed

A digest alone catches neither, because the attacker recomputes it. What
catches them is comparing against state the service has already committed to
its own append-only, externally anchored ledger:

  version   monotonic, and never allowed to go backwards. Rolling back to an
            older file is refused outright, because the ledger remembers a
            higher number and a JSON file cannot argue with it.
  digest    recorded on every change. A replacement at the same version is
            refused; a legitimate change is a visible, attributable ledger
            entry rather than a silent swap.

This is detection and refusal, not prevention: an attacker who owns the
service host owns the ledger too. What it buys is that changing whose keys
count is no longer free and silent — it has to survive the anchored chain,
which is the same bet the audit trail already makes.
"""
import hashlib
import json

REGISTRY_VERSION_KEY = "registry_version:%s"
REGISTRY_DIGEST_KEY = "registry_digest:%s"


class RegistryError(RuntimeError):
    """A registry was rolled back, malformed, or otherwise not acceptable."""


def unwrap(data):
    """Accept both the versioned envelope and a bare mapping.

    Bare files predate versioning and are genuine registries, so they are read
    as version 0 rather than refused — but they can only ever move forward
    from there, and a deployment that cares should export a versioned one.
    """
    if not isinstance(data, dict):
        raise RegistryError("a registry must be a JSON object")
    if "principals" in data and isinstance(data.get("principals"), dict):
        version = data.get("version", 0)
        if not isinstance(version, int) or isinstance(version, bool) or version < 0:
            raise RegistryError(f"registry version must be a non-negative integer, "
                                f"not {version!r}")
        return version, data["principals"]
    return 0, data


def wrap(principals, version):
    return {"version": version, "principals": principals}


def digest(principals):
    """Digest over the principals only, so a version bump alone is visible
    as a version bump rather than masquerading as a content change."""
    return hashlib.sha256(
        json.dumps(principals, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def check(role, version, principals, last_version, last_digest):
    """Compare a loaded registry against what the ledger already recorded.

    Returns (status, detail) where status is one of:

        "unchanged"  same version, same contents
        "updated"    version moved forward; detail carries both digests
        "new"        nothing recorded for this role yet

    Raises RegistryError for the two cases that must stop the service:
    a version that went backwards, and a change in contents that did not
    bother to move the version -- which is what a silent swap looks like.
    """
    current = digest(principals)
    if last_version is None:
        return "new", {"version": version, "digest": current,
                       "principals": len(principals)}

    if version < last_version:
        raise RegistryError(
            f"the {role} registry is version {version}, but this service has "
            f"already run with version {last_version}. A registry cannot go "
            f"backwards: an older copy would reinstate keys that were revoked "
            f"since. If this rollback is deliberate, export a registry with a "
            f"version above {last_version}.")

    if version == last_version:
        if current != last_digest:
            raise RegistryError(
                f"the {role} registry has different contents but the same version "
                f"({version}). Changing whose keys count must move the version, "
                f"so that the change is recorded rather than silently swapped in. "
                f"Recorded digest {last_digest[:16]}..., found {current[:16]}...")
        return "unchanged", {"version": version, "digest": current,
                             "principals": len(principals)}

    return "updated", {"version": version, "previous_version": last_version,
                       "digest": current, "previous_digest": last_digest,
                       "principals": len(principals)}
