import unittest
from pathlib import Path

from mib_oid_extractor import Parser, Tokenizer, extract_from_files, generate_trap_command, OidEntry


FIXTURES = Path(__file__).parent / "fixtures"


class TestMibOidExtractor(unittest.TestCase):
    def test_parser_extracts_description(self):
        text = """
EXAMPLE-MIB DEFINITIONS ::= BEGIN

exampleObject OBJECT-TYPE
    DESCRIPTION
        \"Example description line 1
         line 2.\"
    ::= { enterprises 99999 }

END
"""
        tokens = Tokenizer(text).tokenize()
        parsed = Parser(tokens, "<memory>").parse()

        self.assertEqual(len(parsed.declarations), 1)
        decl = parsed.declarations[0]
        self.assertEqual(decl.name, "exampleObject")
        self.assertEqual(decl.description, "Example description line 1\n         line 2.")

    def test_extract_from_files_resolves_imported_modules(self):
        entries, unresolved_declarations, unresolved_modules = extract_from_files(
            paths=[FIXTURES / "EXAMPLE-DEVICE-MIB.txt"],
            mib_dirs=[FIXTURES],
        )

        self.assertFalse(unresolved_modules)
        self.assertFalse(unresolved_declarations)

        by_name = {entry.name: entry for entry in entries}

        self.assertEqual(by_name["exampleRoot"].oid_str, "1.3.6.1.4.1.99999")
        self.assertEqual(by_name["exampleObjects"].oid_str, "1.3.6.1.4.1.99999.1")
        self.assertEqual(by_name["exampleNotifications"].oid_str, "1.3.6.1.4.1.99999.2")
        self.assertEqual(by_name["exampleDevice"].oid_str, "1.3.6.1.4.1.99999.10")
        self.assertEqual(by_name["exampleScalar"].oid_str, "1.3.6.1.4.1.99999.1.1")
        self.assertEqual(by_name["exampleTrap"].oid_str, "1.3.6.1.4.1.99999.2.1")

    def test_extract_from_files_keeps_description(self):
        entries, _, _ = extract_from_files(
            paths=[FIXTURES / "EXAMPLE-DEVICE-MIB.txt"],
            mib_dirs=[FIXTURES],
        )
        by_name = {entry.name: entry for entry in entries}

        self.assertEqual(by_name["exampleDevice"].description, "Device module identity for tests.")
        self.assertIn("Example scalar object", by_name["exampleScalar"].description)
        self.assertEqual(by_name["exampleTrap"].description, "Example notification.")


class TestGenerateTrapCommand(unittest.TestCase):
    def _make_entry(self, oid: list) -> OidEntry:
        return OidEntry(
            name="exampleTrap",
            kind="NOTIFICATION-TYPE",
            oid=oid,
            source="<memory>",
            module_name="EXAMPLE-MIB",
            description="Example notification.",
        )

    def test_v2c_default(self):
        entry = self._make_entry([1, 3, 6, 1, 4, 1, 99999, 2, 1])
        cmd = generate_trap_command(entry)
        self.assertEqual(cmd, "snmptrap -v 2c -c public localhost '' 1.3.6.1.4.1.99999.2.1")

    def test_v2c_custom_host_and_community(self):
        entry = self._make_entry([1, 3, 6, 1, 4, 1, 99999, 2, 1])
        cmd = generate_trap_command(entry, host="192.168.1.1", community="private", version="2c")
        self.assertEqual(cmd, "snmptrap -v 2c -c private 192.168.1.1 '' 1.3.6.1.4.1.99999.2.1")

    def test_v1(self):
        entry = self._make_entry([1, 3, 6, 1, 4, 1, 99999, 2, 1])
        cmd = generate_trap_command(entry, version="1")
        self.assertEqual(
            cmd,
            'snmptrap -v 1 -c public localhost 1.3.6.1.4.1.99999.2 "" 6 1 0',
        )

    def test_v1_single_component_oid(self):
        entry = self._make_entry([1])
        cmd = generate_trap_command(entry, version="1")
        self.assertEqual(cmd, 'snmptrap -v 1 -c public localhost 1 "" 6 0 0')

    def test_v3(self):
        entry = self._make_entry([1, 3, 6, 1, 4, 1, 99999, 2, 1])
        cmd = generate_trap_command(entry, community="trapuser", version="3")
        self.assertEqual(
            cmd,
            "snmptrap -v 3 -u trapuser -l noAuthNoPriv localhost '' 1.3.6.1.4.1.99999.2.1",
        )

    def test_unsupported_version_raises(self):
        entry = self._make_entry([1, 3, 6, 1, 4, 1, 99999, 2, 1])
        with self.assertRaises(ValueError):
            generate_trap_command(entry, version="99")

    def test_from_fixture_notification(self):
        entries, _, _ = extract_from_files(
            paths=[FIXTURES / "EXAMPLE-DEVICE-MIB.txt"],
            mib_dirs=[FIXTURES],
        )
        notifications = [e for e in entries if e.kind == "NOTIFICATION-TYPE"]
        self.assertEqual(len(notifications), 1)
        cmd = generate_trap_command(notifications[0])
        self.assertEqual(cmd, "snmptrap -v 2c -c public localhost '' 1.3.6.1.4.1.99999.2.1")


if __name__ == "__main__":
    unittest.main()
