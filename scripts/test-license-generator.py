#!/usr/bin/env python3
"""Synthetic license tests. Never read the user's registry or signing key."""
import argparse
import base64
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("license_manager", Path(__file__).with_name("generate_license_v2.py"))
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class LicenseManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lexflow-license-test-")
        self.directory = Path(self.temporary.name)
        self.paths = patch.multiple(
            manager, REGISTRY_FILE=self.directory / "registry.enc",
            REGISTRY_SALT_FILE=self.directory / "salt",
        )
        self.paths.start()
        self.private = manager.ed25519.Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            manager.serialization.Encoding.Raw, manager.serialization.PublicFormat.Raw)
        self.payload = {"c": "Studio sintetico", "s": "Studio sintetico", "a": "Test",
                        "t": "Avv.", "id": "test-1", "n": "a" * 32, "e": 4_102_444_799_999, "g": 2}
        self.entries = [{"id": "test-1", "studio": "Synthetic confidential name", "status": "issued"}]
        self.password = "SyntheticRegistryPassword_123!"

    def tearDown(self):
        self.paths.stop()
        self.temporary.cleanup()

    def test_public_constants_agree(self):
        self.assertEqual(len(manager.expected_public_key()), 32)

    def test_local_key_configuration_checks_issuer_path_and_permissions(self):
        base = self.directory.resolve()
        key = base / "issuer.pem"
        key.write_text("synthetic placeholder; this test must not read the private file")
        key.chmod(0o600)
        metadata = base / "active-license-key.json"
        config = {"public_key_hex": self.public.hex(), "private_key_file": str(key)}
        with patch.object(manager, "LOCAL_KEY_DIR", base), \
             patch.object(manager, "expected_public_key", return_value=self.public):
            metadata.write_text(json.dumps(config))
            self.assertEqual(manager.configured_private_key_path(), key)
            for changed in ({"public_key_hex": "00" * 32},
                            {"private_key_file": str(base.parent / "outside.pem")},
                            {"private_key_file": "relative.pem"}):
                metadata.write_text(json.dumps(dict(config, **changed)))
                with self.assertRaises(ValueError):
                    manager.configured_private_key_path()
            metadata.write_text(json.dumps(config))
            if os.name != "nt":
                key.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "0600"):
                    manager.configured_private_key_path()
                key.chmod(0o600)
                link = base / "link.pem"
                link.symlink_to(key)
                metadata.write_text(json.dumps(dict(config, private_key_file=str(link))))
                with self.assertRaises(ValueError):
                    manager.configured_private_key_path()

    def test_local_key_generation_uses_configured_file_without_secret_prompt(self):
        key = self.directory / "synthetic-key.pem"
        key.write_bytes(self.private.private_bytes(manager.serialization.Encoding.PEM,
            manager.serialization.PrivateFormat.PKCS8, manager.serialization.NoEncryption()))
        answers = ["Studio sintetico", "Avvocato Test", "", "test-local", "2099-12-31", "0", ""]
        output = io.StringIO()
        with patch.object(manager, "expected_public_key", return_value=self.public), \
             patch.object(manager, "configured_private_key_path", return_value=key), \
             patch.object(manager, "secret_prompt", side_effect=AssertionError("manual key prompt")), \
             patch.object(manager, "get_password", return_value=self.password), \
             patch("builtins.input", side_effect=answers), redirect_stdout(output):
            self.assertEqual(manager.main(["generate", "--local-key"]), 0)
        token = next(line for line in output.getvalue().splitlines() if line.startswith("LXFW."))
        self.assertEqual(manager.verify_token(token, self.public)["id"], "test-local")
        self.assertNotIn("PRIVATE KEY", output.getvalue())

    def test_signature_and_altered_token(self):
        token = manager.sign_token(self.private, self.public, self.payload)
        self.assertEqual(manager.verify_token(token, self.public), self.payload)
        parts = token.split(".")
        altered = dict(self.payload, c="Attacker")
        parts[1] = base64.urlsafe_b64encode(json.dumps(altered).encode()).decode().rstrip("=")
        with self.assertRaisesRegex(ValueError, "Firma"):
            manager.verify_token(".".join(parts), self.public)
        other = manager.ed25519.Ed25519PrivateKey.generate()
        other_public = other.public_key().public_bytes(manager.serialization.Encoding.Raw, manager.serialization.PublicFormat.Raw)
        with self.assertRaises(ValueError):
            manager.sign_token(self.private, other_public, self.payload)
        with self.assertRaises(ValueError):
            manager.verify_token(token, other_public)

    def test_private_key_formats_reject_fake_der(self):
        seed = self.private.private_bytes(manager.serialization.Encoding.Raw, manager.serialization.PrivateFormat.Raw, manager.serialization.NoEncryption())
        pem = self.private.private_bytes(manager.serialization.Encoding.PEM, manager.serialization.PrivateFormat.PKCS8, manager.serialization.NoEncryption())
        der = self.private.private_bytes(manager.serialization.Encoding.DER, manager.serialization.PrivateFormat.PKCS8, manager.serialization.NoEncryption())
        for raw in (seed.hex(), base64.b64encode(seed).decode(), pem.decode(), base64.b64encode(der).decode()):
            self.assertEqual(manager._parse_private_key(raw)[1], self.public)
        with self.assertRaises(ValueError):
            manager._parse_private_key(base64.b64encode(b"\x30" + b"x" * 47).decode())

    def test_invalid_payload_and_expiry_end_of_day_utc(self):
        for field, value in (("g", -1), ("g", 3651), ("g", True), ("c", "\x1b[31m"), ("id", ""), ("e", 0)):
            with self.assertRaises(ValueError):
                manager.sign_token(self.private, self.public, dict(self.payload, **{field: value}))
        expiry, label = manager._parse_expiry("2030-01-01")
        self.assertEqual(label, "2030-01-01")
        self.assertEqual(expiry, 1_893_542_399_999)
        with self.assertRaises(ValueError):
            manager.verify_token("A" * (manager.MAX_TOKEN_BYTES + 1), self.public)

    def test_registry_roundtrip_authentication_and_private_mode(self):
        manager.save_registry(self.password, self.entries)
        encrypted = manager.REGISTRY_FILE.read_bytes()
        self.assertTrue(encrypted.startswith(manager.MAGIC))
        self.assertNotIn(b"Synthetic confidential name", encrypted)
        self.assertEqual(manager.load_registry(self.password), self.entries)
        if os.name != "nt":
            self.assertEqual(manager.REGISTRY_FILE.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            manager.load_registry("wrong-password")
        self.assertEqual(manager.REGISTRY_FILE.read_bytes(), encrypted)
        manager.REGISTRY_FILE.write_bytes(encrypted[:-1] + bytes([encrypted[-1] ^ 1]))
        with self.assertRaises(ValueError):
            manager.load_registry(self.password)

    def test_both_legacy_layouts_migrate_without_losing_entries_or_salt(self):
        salt, nonce = b"s" * 32, b"n" * 12
        encoded = json.dumps(self.entries, sort_keys=True, separators=(",", ":")).encode()
        checksum = manager.hashlib.sha256(salt + b":INTEGRITY:" + encoded).hexdigest()
        plaintext = json.dumps({"entries": self.entries, "hmac": checksum}).encode()
        ciphertext = manager.AESGCM(manager.derive_registry_key(self.password, salt)).encrypt(nonce, plaintext, None)
        # Old split layout is normally MUCH longer than 44 bytes.
        for prefix in (salt, b""):
            with self.subTest(embedded=bool(prefix)):
                if prefix:
                    manager.REGISTRY_SALT_FILE.unlink(missing_ok=True)
                else:
                    manager.REGISTRY_SALT_FILE.write_bytes(salt)
                before = prefix + nonce + ciphertext
                manager.REGISTRY_FILE.write_bytes(before)
                self.assertEqual(manager.load_registry(self.password), self.entries)
                self.assertEqual(manager.REGISTRY_FILE.read_bytes(), before)
                manager.save_registry(self.password, self.entries)
                self.assertEqual(manager.load_registry(self.password), self.entries)
                if not prefix:
                    self.assertEqual(manager.REGISTRY_SALT_FILE.read_bytes(), salt)

    def test_atomic_failure_and_no_overwrite(self):
        manager.REGISTRY_FILE.write_bytes(b"original")
        with patch.object(manager.os, "replace", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                manager.atomic_private_write(manager.REGISTRY_FILE, b"new")
        self.assertEqual(manager.REGISTRY_FILE.read_bytes(), b"original")
        self.assertFalse(list(self.directory.glob(".lexflow-stage-*")))
        with self.assertRaises(FileExistsError):
            manager.atomic_private_write(manager.REGISTRY_FILE, b"new", replace=False)
        self.assertEqual(manager.REGISTRY_FILE.read_bytes(), b"original")

    def test_valid_embedded_legacy_ignores_corrupt_unused_salt(self):
        salt, nonce = b"s" * 32, b"n" * 12
        plaintext = json.dumps({"entries": self.entries}).encode()
        ciphertext = manager.AESGCM(manager.derive_registry_key(self.password, salt)).encrypt(nonce, plaintext, None)
        manager.REGISTRY_FILE.write_bytes(salt + nonce + ciphertext)
        manager.REGISTRY_SALT_FILE.write_bytes(b"unused corrupt historical salt" * 20)
        self.assertEqual(manager.load_registry(self.password), self.entries)

    def test_registry_writer_cannot_exceed_reader_entry_limit(self):
        manager.REGISTRY_FILE.write_bytes(b"preserved")
        with patch.object(manager, "MAX_REGISTRY_ENTRIES", 1):
            with self.assertRaises(ValueError):
                manager.save_registry(self.password, [{"id": "one"}, {"id": "two"}])
        self.assertEqual(manager.REGISTRY_FILE.read_bytes(), b"preserved")

    def test_nuke_authentication_failure_preserves_registry(self):
        manager.save_registry(self.password, self.entries)
        before = manager.REGISTRY_FILE.read_bytes()
        with patch.object(manager, "get_password", return_value="wrong"), \
             patch("builtins.input", side_effect=AssertionError("confirmation before authentication")):
            with self.assertRaises(ValueError):
                manager.cmd_registry(argparse.Namespace(command="nuke"))
        self.assertEqual(manager.REGISTRY_FILE.read_bytes(), before)

    def test_secret_prompt_rejects_visible_input_fallback(self):
        def unsafe_fallback(_prompt):
            manager.warnings.warn("echo unavailable", manager.getpass.GetPassWarning)
            self.fail("visible input fallback reached")
        with patch.object(manager.getpass, "getpass", side_effect=unsafe_fallback):
            with self.assertRaisesRegex(ValueError, "input nascosto"):
                manager.secret_prompt("Secret: ")

    @unittest.skipIf(os.name == "nt", "Unix symlink/FIFO boundary")
    def test_sensitive_reads_and_writes_reject_symlinks_and_fifo(self):
        original = self.directory / "original"
        original.write_bytes(b"preserved")
        manager.REGISTRY_FILE.symlink_to(original)
        with self.assertRaises(ValueError):
            manager.load_registry(self.password)
        with self.assertRaises(ValueError):
            manager.atomic_private_write(manager.REGISTRY_FILE, b"replacement")
        self.assertEqual(original.read_bytes(), b"preserved")
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            manager.read_private_file(fifo, 100)
        with self.assertRaises(ValueError):
            manager.read_private_file(original, 3)

    def test_registry_lock_excludes_concurrent_writer(self):
        with manager.registry_lock():
            with self.assertRaises(ValueError):
                with manager.registry_lock():
                    self.fail("second writer acquired the lock")
        with manager.registry_lock():
            pass

    def test_verify_checks_signature_without_reading_registry(self):
        token = manager.sign_token(self.private, self.public, self.payload)
        with patch.object(manager, "expected_public_key", return_value=self.public), \
             patch.object(manager, "load_registry", side_effect=AssertionError("registry read")), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(manager.cmd_verify(argparse.Namespace(token=token)), 0)
        with patch.object(manager, "expected_public_key", return_value=self.public), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(manager.main(["verify", "LXFW.a.b"]), 1)
        self.assertFalse(manager.REGISTRY_FILE.exists())

    def test_generate_registers_before_display_and_rejects_wrong_key(self):
        seed = self.private.private_bytes(manager.serialization.Encoding.Raw, manager.serialization.PrivateFormat.Raw, manager.serialization.NoEncryption()).hex()
        answers = ["Studio sintetico", "Avvocato Test", "", "test-issued", "2099-12-31", "0", ""]
        output = io.StringIO()
        with patch.object(manager, "expected_public_key", return_value=self.public), \
             patch.object(manager.getpass, "getpass", return_value=seed), \
             patch.object(manager, "get_password", return_value=self.password), \
             patch("builtins.input", side_effect=answers), redirect_stdout(output):
            manager.cmd_generate(argparse.Namespace(private_key_file=None))
        token = next(line for line in output.getvalue().splitlines() if line.startswith("LXFW."))
        self.assertEqual(manager.verify_token(token, self.public)["id"], "test-issued")
        entries = manager.load_registry(self.password)
        self.assertEqual(entries[0]["burn_hash"], manager.compute_key_hash(token))
        self.assertNotIn(seed, output.getvalue())
        before = manager.REGISTRY_FILE.read_bytes()
        with patch.object(manager, "expected_public_key", return_value=b"\0" * 32), \
             patch.object(manager.getpass, "getpass", return_value=seed), \
             patch("builtins.input", side_effect=AssertionError("prompt after mismatched key")):
            with self.assertRaisesRegex(ValueError, "diversa"):
                manager.cmd_generate(argparse.Namespace(private_key_file=None))
        self.assertEqual(manager.REGISTRY_FILE.read_bytes(), before)

    def test_withdrawal_preserves_hash_and_does_not_claim_remote_revocation(self):
        token = manager.sign_token(self.private, self.public, self.payload)
        self.entries[0]["burn_hash"] = manager.compute_key_hash(token)
        manager.save_registry(self.password, self.entries)
        output = io.StringIO()
        with patch.object(manager, "get_password", return_value=self.password), \
             patch("builtins.input", return_value="BURN"), redirect_stdout(output):
            manager.cmd_registry(argparse.Namespace(command="burn", id="test-1"))
        entry = manager.load_registry(self.password)[0]
        self.assertEqual(entry["status"], "burned")
        self.assertEqual(entry["burn_hash"], manager.compute_key_hash(token))
        self.assertEqual(manager.verify_token(token, self.public), self.payload)
        self.assertIn("continua a funzionare offline", output.getvalue())
        self.assertTrue(list(self.directory.glob(".lexflow-registry-*.bak.enc")))

    def test_csv_injection_and_existing_file_protected(self):
        for value in ("=1+1", " @SUM(A1)", "+1", "-1", "\tvalue", "\rvalue"):
            self.assertTrue(manager.csv_cell(value).startswith("'"))
        self.assertEqual(manager.csv_cell("Studio Rossi"), "Studio Rossi")
        manager.save_registry(self.password, [{"id": "=1+1", "studio": "Test"}])
        output = self.directory / "export.csv"
        with patch.object(manager, "get_password", return_value=self.password), redirect_stdout(io.StringIO()):
            manager.cmd_registry(argparse.Namespace(command="export", output=output))
            self.assertIn("'=1+1", output.read_text(encoding="utf-8-sig"))
            with self.assertRaises(FileExistsError):
                manager.cmd_registry(argparse.Namespace(command="export", output=output))


if __name__ == "__main__":
    unittest.main()
