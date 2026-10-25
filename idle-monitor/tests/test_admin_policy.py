"""Authorization and policy reload regressions; no SMTP or machine changes."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import idle_monitor as monitor


class AdminPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.path = self.folder / 'config.json'
        self.config = dict(monitor.DEFAULTS, email='it@example.com', email_password='test-secret')
        self.path.write_text(json.dumps(self.config), encoding='utf-8')

    def app(self, editor=False):
        with patch.object(monitor, 'is_admin', return_value=True):
            app = monitor.App(self.config, self.path, self.folder, editor=editor)
            if editor:
                app.settings_lock.save_password('test settings password', 'test settings password')
            return app

    def test_standard_user_cannot_write_or_sign_in_or_change_whitelist(self):
        app = self.app()
        before = self.path.read_bytes()
        with patch.object(monitor, 'is_admin', return_value=False), \
             patch.object(monitor, 'smtp_action') as smtp:
            for update in ({'idle_threshold_minutes': 1}, {'app_whitelist': ['chrome.exe']},
                           {'email': 'other@example.com'}):
                with self.assertRaises(PermissionError): app.commit(update)
                with self.assertRaises(PermissionError): app.sign_in(update)
            with self.assertRaises(PermissionError): monitor.write_config(self.path, {})
            smtp.assert_not_called()
        self.assertEqual(before, self.path.read_bytes())

    def test_admin_editor_required_even_for_elevated_monitor(self):
        app = self.app()
        with patch.object(monitor, 'is_admin', return_value=True):
            with self.assertRaises(PermissionError): app.commit({'idle_threshold_minutes': 5})
        with patch.object(monitor, 'is_admin', return_value=False):
            with self.assertRaises(PermissionError): monitor.App(self.config, self.path, self.folder, editor=True)

    def test_admin_changes_are_loaded_by_running_employee_app(self):
        editor, employee = self.app(editor=True), self.app()
        with patch.object(monitor, 'is_admin', return_value=True):
            editor.commit({'idle_threshold_minutes': 5, 'app_whitelist': ['Chrome.exe']})
        employee.reload_policy()
        self.assertEqual(employee.snapshot()['idle_threshold_minutes'], 5)
        self.assertEqual(employee.snapshot()['app_whitelist'], ['chrome.exe'])

    def test_changed_credentials_invalidate_old_authentication(self):
        app = self.app()
        app.signed_in = True
        self.path.write_text(json.dumps(dict(self.config, email_password='replacement')), encoding='utf-8')
        app.reload_policy()
        self.assertFalse(app.signed_in)
        self.assertTrue(app.verify_pending)
        self.assertEqual(app.epoch, 1)

    def test_corrupt_and_missing_policy_stop_sending_and_recovery_reverifies(self):
        app = self.app()
        for corrupt in ('broken', '[]', '{"smtp_port": 0}'):
            app.signed_in = True
            self.path.write_text(corrupt, encoding='utf-8')
            with patch.object(monitor, 'smtp_action') as smtp:
                with self.assertRaises(RuntimeError): app.send_current(100)
                smtp.assert_not_called()
            self.assertFalse(app.signed_in)
            self.assertEqual(self.path.read_text(encoding='utf-8'), corrupt)
            self.path.write_text(json.dumps(self.config), encoding='utf-8')
            app.reload_policy()
            self.assertTrue(app.verify_pending)
            self.assertFalse(app.signed_in)
        self.path.unlink()
        app.reload_policy()
        self.assertFalse(app.verify_pending)
        self.assertFalse(self.path.exists())

    def test_employee_environment_cannot_override_managed_password(self):
        smtp = Mock()
        with patch.dict(os.environ, {'IDLE_MONITOR_PASSWORD': 'employee-override'}), \
             patch.object(monitor.smtplib, 'SMTP', return_value=smtp):
            monitor.smtp_action(self.config)
        smtp.login.assert_called_once_with('it@example.com', 'test-secret')

    def test_resaving_identical_settings_retries_rejected_account(self):
        app = self.app()
        app.signed_in, app.verify_pending = False, False
        # Model an atomic admin save with a later file modification time.
        os.utime(self.path, ns=(self.path.stat().st_atime_ns, app.policy_stamp + 1000000000))
        app.reload_policy()
        self.assertTrue(app.verify_pending)

    def test_command_line_overrides_are_refused_before_loading_policy(self):
        for args in (['--config', str(self.path)], ['--threshold-minutes', '1']):
            with patch.object(sys, 'argv', ['idle-monitor'] + args), \
                 patch.object(monitor, 'machine_config_path') as path:
                with self.assertRaises(PermissionError): monitor.main()
                path.assert_not_called()


if __name__ == '__main__':
    unittest.main()
