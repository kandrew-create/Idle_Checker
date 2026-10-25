"""Password storage, unlock, recovery and mutation protection without machine writes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from settings_security import SettingsLock, password_record, unlock_dialog
import idle_monitor as monitor

PASSWORD = 'a strong settings password'


class SettingsSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'settings-password.json'
        self.admin = Mock()
        self.lock = SettingsLock(self.path, self.admin)

    def setup_password(self):
        self.lock.save_password(PASSWORD, PASSWORD)

    def test_unique_salts_and_no_plaintext(self):
        self.setup_password()
        first = self.path.read_text()
        self.assertNotIn(PASSWORD, first)
        self.assertNotEqual(json.loads(first)['salt'], password_record(PASSWORD)['salt'])
        self.lock.lock()
        with self.assertRaises(PermissionError): self.lock.authorize()
        self.lock.unlock(PASSWORD)
        self.lock.authorize()

    def test_wrong_password_locks_session_and_limits_attempts(self):
        self.setup_password()
        for _ in range(5):
            with self.assertRaises(PermissionError): self.lock.unlock('wrong')
        with self.assertRaises(PermissionError): self.lock.unlock(PASSWORD)
        with self.assertRaises(PermissionError): self.lock.authorize()

    def test_change_requires_current_password_and_new_confirmation(self):
        self.setup_password()
        original = self.path.read_bytes()
        with self.assertRaises(PermissionError): self.lock.save_password('new password here', 'new password here', current='wrong')
        with self.assertRaises(ValueError): self.lock.save_password('new password here', 'different', current=PASSWORD)
        self.assertEqual(original, self.path.read_bytes())
        self.lock.save_password('new password here', 'new password here', current=PASSWORD)
        self.lock.lock()
        with self.assertRaises(PermissionError): self.lock.unlock(PASSWORD)
        self.lock.unlock('new password here')

    def test_missing_and_corrupt_records_cannot_authorize(self):
        with self.assertRaises(PermissionError): self.lock.authorize()
        self.setup_password()
        for content in ('bad', '[]', '{"version":1,"salt":"bad","digest":"bad"}'):
            self.path.write_text(content)
            with self.assertRaises((ValueError, PermissionError)): self.lock.authorize()
            with self.assertRaises(ValueError): self.lock.unlock(PASSWORD)
        self.lock.save_password('recovery password here', 'recovery password here', recovery=True)
        self.lock.authorize()

    def test_recovery_is_admin_only_and_invalidates_other_editor(self):
        self.setup_password()
        other = SettingsLock(self.path, self.admin)
        other.unlock(PASSWORD)
        self.admin.side_effect = PermissionError('Administrator required')
        with self.assertRaises(PermissionError): self.lock.save_password('recovery password here', 'recovery password here', recovery=True)
        self.admin.side_effect = None
        self.lock.save_password('recovery password here', 'recovery password here', recovery=True)
        with self.assertRaises(PermissionError): other.authorize()
        other.unlock('recovery password here')

    def test_rejected_write_preserves_existing_password(self):
        self.setup_password()
        original = self.path.read_bytes()
        with patch('settings_security.os.replace', side_effect=OSError('failure')):
            with self.assertRaises(OSError): self.lock.save_password('recovery password here', 'recovery password here', recovery=True)
        self.assertEqual(original, self.path.read_bytes())
        self.assertFalse(list(self.path.parent.glob('*.tmp')))

    def test_short_and_mismatched_passwords_do_not_initialize_lock(self):
        for value, confirmation in [('short', 'short'), (PASSWORD, 'different')]:
            with self.assertRaises(ValueError): self.lock.save_password(value, confirmation)
        self.assertFalse(self.path.exists())

    def test_first_open_sets_password_through_gui_and_cancel_does_not_save(self):
        with patch('tkinter.simpledialog.askstring', side_effect=[None]):
            self.assertFalse(unlock_dialog(None, self.lock))
        self.assertFalse(self.path.exists())
        with patch('tkinter.simpledialog.askstring', side_effect=[PASSWORD, PASSWORD]):
            self.assertTrue(unlock_dialog(None, self.lock))
        self.lock.authorize()

    def test_locked_elevated_editor_cannot_change_settings_or_authenticate(self):
        config = dict(monitor.DEFAULTS, email='test@example.com', email_password='mock')
        path = self.path.parent / 'config.json'
        with patch.object(monitor, 'is_admin', return_value=True), patch.object(monitor, 'smtp_action') as smtp:
            app = monitor.App(config, path, self.path.parent, editor=True)
            with self.assertRaises(PermissionError): app.commit({'idle_threshold_minutes': 5})
            with self.assertRaises(PermissionError): app.sign_in({})
            with self.assertRaises(PermissionError): app.send_current()
            smtp.assert_not_called()
        self.assertFalse(path.exists())


if __name__ == '__main__': unittest.main()
