import unittest

from pwnman.pwnman.models import ConnectionProfile


class ConnectionProfileTest(unittest.TestCase):
    def test_defaults(self):
        p = ConnectionProfile(name="dev")
        self.assertEqual(p.name, "dev")
        self.assertEqual(p.host, "")
        self.assertEqual(p.port, 22)
        self.assertEqual(p.username, "pi")
        self.assertEqual(p.password, "")
        self.assertEqual(p.key_path, "")
        self.assertEqual(p.lcd_user, "changeme")
        self.assertEqual(p.lcd_pass, "changeme")

    def test_roundtrip(self):
        p = ConnectionProfile(
            name="garage",
            host="10.0.0.9",
            port=2222,
            username="admin",
            password="s3cret",
            key_path="/home/x/id_ed25519",
            lcd_url="http://10.0.0.9:8080/",
            lcd_user="u",
            lcd_pass="pw",
        )
        self.assertEqual(ConnectionProfile.from_dict(p.to_dict()), p)

    def test_from_dict_ignores_unknown_keys(self):
        p = ConnectionProfile.from_dict(
            {"name": "x", "host": "1.2.3.4", "bogus": 1, "extra": "y"}
        )
        self.assertEqual(p.name, "x")
        self.assertEqual(p.host, "1.2.3.4")

    def test_from_dict_missing_name_gets_placeholder(self):
        p = ConnectionProfile.from_dict({"host": "1.2.3.4"})
        self.assertEqual(p.name, "unnamed")

    def test_from_dict_coerces_bad_port(self):
        self.assertEqual(ConnectionProfile.from_dict({"name": "a", "port": "oops"}).port, 22)
        self.assertEqual(ConnectionProfile.from_dict({"name": "a", "port": None}).port, 22)
        self.assertEqual(ConnectionProfile.from_dict({"name": "a", "port": "2222"}).port, 2222)

    def test_from_dict_handles_none(self):
        p = ConnectionProfile.from_dict(None)
        self.assertEqual(p.name, "unnamed")


if __name__ == "__main__":
    unittest.main()
