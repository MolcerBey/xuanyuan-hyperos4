"""Compare contents, links, ownership, modes and xattrs of Android image trees."""
import hashlib
import os
import pathlib
import stat


def snapshot(root):
    root = pathlib.Path(root)
    result = {}
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = pathlib.Path(parent, name)
            info = path.lstat()
            item = {"mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                    "xattrs": {key: os.getxattr(path, key, follow_symlinks=False).hex()
                               for key in sorted(os.listxattr(path, follow_symlinks=False))}}
            if stat.S_ISREG(info.st_mode):
                with path.open("rb") as stream:
                    item["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
                item["size"] = info.st_size
            elif stat.S_ISLNK(info.st_mode):
                item["link"] = os.readlink(path)
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(f"Unexpected special file: {path}")
            result[str(path.relative_to(root))] = item
    return result


def compare_retained(before, after, removed, changed, added):
    removed_names = {name for name in before if any(name == p or name.startswith(p + "/") for p in removed)}
    expected_names = (set(before) - removed_names) | set(added)
    if set(after) != expected_names:
        raise ValueError(f"Unexpected tree entries: missing={sorted(expected_names - set(after))}, extra={sorted(set(after) - expected_names)}")
    for name in set(before) - removed_names:
        first, second = before[name].copy(), after[name].copy()
        if name in changed:
            first.pop("sha256", None); second.pop("sha256", None)
            first.pop("size", None); second.pop("size", None)
        if first != second:
            raise ValueError(f"Unapproved contents or metadata change: {name}")
    return len(set(before) - removed_names - set(changed))
