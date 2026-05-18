import unittest
from pathlib import Path

from mib_oid_extractor import Parser, Tokenizer, extract_from_files


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


if __name__ == "__main__":
    unittest.main()
