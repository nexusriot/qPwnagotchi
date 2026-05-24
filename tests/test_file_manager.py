import posixpath
import stat
import unittest

from pwnman.pwnman.file_manager import (
    encode_drag_payload,
    decode_drag_payload,
    looks_binary,
    sftp_rmtree,
)


class DragPayloadTest(unittest.TestCase):
    def test_roundtrip(self):
        blob = encode_drag_payload("local", ["a.txt", "dir"])
        self.assertEqual(decode_drag_payload(blob), ("local", ["a.txt", "dir"]))

    def test_rejects_unknown_side(self):
        blob = encode_drag_payload("bogus", ["x"])
        side, names = decode_drag_payload(blob)
        self.assertEqual(side, "")
        self.assertEqual(names, ["x"])

    def test_garbage_is_safe(self):
        self.assertEqual(decode_drag_payload(b"not json"), ("", []))
        self.assertEqual(decode_drag_payload(b"[1,2,3]"), ("", []))

    def test_filters_non_string_names(self):
        blob = b'{"side":"remote","names":["ok",1,null,"two"]}'
        self.assertEqual(decode_drag_payload(blob), ("remote", ["ok", "two"]))


class BinaryGuardTest(unittest.TestCase):
    def test_text(self):
        self.assertFalse(looks_binary(b"hello\nworld\n"))

    def test_binary(self):
        self.assertTrue(looks_binary(b"PK\x03\x04\x00\x00"))


class _S:
    def __init__(self, mode):
        self.st_mode = mode


class _Attr:
    def __init__(self, name, is_dir):
        self.filename = name
        self.st_mode = stat.S_IFDIR if is_dir else stat.S_IFREG


class FakeSFTP:
    """tree maps full posix path -> ('dir', [child_paths]) | ('file', None)."""

    def __init__(self, tree):
        self.tree = tree
        self.removed = []
        self.rmdir_calls = []

    def lstat(self, path):
        node = self.tree.get(path)
        if node is None:
            raise FileNotFoundError(path)
        return _S(stat.S_IFDIR if node[0] == "dir" else stat.S_IFREG)

    def listdir_attr(self, path):
        children = self.tree[path][1]
        return [
            _Attr(posixpath.basename(c), self.tree[c][0] == "dir")
            for c in children
        ]

    def rmdir(self, path):
        self.rmdir_calls.append(path)

    def remove(self, path):
        self.removed.append(path)


class SftpRmtreeTest(unittest.TestCase):
    def test_recursive_depth_first(self):
        tree = {
            "/a": ("dir", ["/a/b", "/a/c"]),
            "/a/b": ("file", None),
            "/a/c": ("dir", ["/a/c/d"]),
            "/a/c/d": ("file", None),
        }
        sftp = FakeSFTP(tree)
        sftp_rmtree(sftp, "/a")
        self.assertEqual(sorted(sftp.removed), ["/a/b", "/a/c/d"])
        # children dirs removed before their parent
        self.assertEqual(sftp.rmdir_calls, ["/a/c", "/a"])

    def test_single_file(self):
        sftp = FakeSFTP({"/x.txt": ("file", None)})
        sftp_rmtree(sftp, "/x.txt")
        self.assertEqual(sftp.removed, ["/x.txt"])
        self.assertEqual(sftp.rmdir_calls, [])

    def test_missing_path_is_noop(self):
        sftp = FakeSFTP({})
        sftp_rmtree(sftp, "/gone")  # must not raise
        self.assertEqual(sftp.removed, [])
        self.assertEqual(sftp.rmdir_calls, [])

    def test_empty_dir(self):
        sftp = FakeSFTP({"/d": ("dir", [])})
        sftp_rmtree(sftp, "/d")
        self.assertEqual(sftp.rmdir_calls, ["/d"])


if __name__ == "__main__":
    unittest.main()
