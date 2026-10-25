"""Report and email checks with no external SMTP or Office calls."""
from pathlib import Path
import smtplib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import activity_report as reports
import idle_monitor as monitor


def row(hwnd=10, title='Example document'):
    return dict(hwnd=hwnd, pid=123, application='example.exe', title=title,
                active=True, save_status=reports.title_save_status(title))


class ReportTests(unittest.TestCase):
    def test_whitelist_filters_all_matching_windows_before_office_probe(self):
        rows = [dict(row(hwnd=1), application='WINWORD.EXE'),
                dict(row(hwnd=2), application='winword.exe'), row(hwnd=3)]
        with patch.object(reports, 'open_windows', return_value=rows), \
             patch.object(reports, 'office_status', return_value=[]) as probe:
            report = reports.collect_report(['WinWord.exe'])
        self.assertEqual(report['windows'], [rows[2]])
        probe.assert_called_once_with([rows[2]])
        self.assertNotIn('winword', reports.format_report(report).casefold())

    def test_whitelist_does_not_match_substrings_and_can_be_removed(self):
        rows = [row(), dict(row(hwnd=2), application='other-example.exe')]
        self.assertEqual(reports.monitored_windows(rows, ['example.exe']), [rows[1]])
        self.assertEqual(reports.monitored_windows(rows, []), rows)

    def test_whitelist_validation_and_old_config(self):
        config = dict(monitor.DEFAULTS, app_whitelist=[' Chrome.exe ', 'chrome.EXE', 'Spotify.exe'])
        self.assertEqual(monitor.validate(config, require_email=False)['app_whitelist'], ['chrome.exe', 'spotify.exe'])
        del config['app_whitelist']
        self.assertEqual(monitor.validate(config, require_email=False)['app_whitelist'], [])
        for invalid in ('chrome.exe', [12], ['C:\\Apps\\chrome.exe'], ['*.exe'], [''], ['.exe'], ['app.exe\nother.exe']):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                monitor.validate(dict(config, app_whitelist=invalid), require_email=False)

    def test_no_marker_does_not_imply_saved(self):
        self.assertEqual(reports.title_save_status('saved-looking.docx - Word'), reports.UNKNOWN)
        self.assertIn('Possible unsaved', reports.title_save_status('*notes - Notepad'))

    def test_saved_modified_never_saved_and_unmatched(self):
        rows = [row(hwnd=n) for n in range(1, 5)]
        reports.apply_document_status(rows, [
            dict(hwnd=1, has_path=True, saved=True),
            dict(hwnd=2, has_path=True, saved=False),
            dict(hwnd=3, has_path=False, saved=True),
        ])
        self.assertTrue(rows[0]['save_status'].startswith('Saved'))
        self.assertTrue(rows[1]['save_status'].startswith('Unsaved'))
        self.assertTrue(rows[2]['save_status'].startswith('Never saved'))
        self.assertEqual(rows[3]['save_status'], reports.UNKNOWN)

    def test_shared_handle_cannot_claim_saved(self):
        rows = [row()]
        reports.apply_document_status(rows, [dict(hwnd=10, has_path=True, saved=True),
                                             dict(hwnd=10, has_path=True, saved=False)])
        self.assertTrue(rows[0]['save_status'].startswith('Unknown'))

    def test_office_timeout_preserves_unknown(self):
        with patch.object(reports, 'open_windows', return_value=[row()]), \
             patch.object(reports, 'office_status', side_effect=subprocess.TimeoutExpired('probe', 4)):
            report = reports.collect_report()
        self.assertEqual(report['windows'][0]['save_status'], reports.UNKNOWN)
        self.assertEqual(report['error'], '')

    def test_enumeration_failure_is_reported(self):
        with patch.object(reports, 'open_windows', side_effect=OSError()):
            report = reports.collect_report()
        self.assertIn('could not be read', reports.format_report(report))

    def test_report_preserves_unicode_and_marks_active(self):
        text = reports.format_report(dict(captured_at='test', windows=[row(title='\u6d4b\u8bd5.docx')], error=''))
        self.assertIn('\u6d4b\u8bd5.docx', text)
        self.assertIn('ACTIVE AT CAPTURE', text)
        self.assertIn('does not mean saved', text)


class EmailTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(monitor.DEFAULTS, email='test@example.com', email_password='fake')
        self.report = dict(captured_at='2026-10-23T12:00:00', windows=[row()], error='')

    def test_sign_in_does_not_collect_or_send(self):
        smtp = Mock()
        with patch.object(monitor.smtplib, 'SMTP', return_value=smtp), \
             patch.object(monitor, 'collect_report') as collect:
            monitor.smtp_action(self.config)
        smtp.login.assert_called_once()
        smtp.send_message.assert_not_called()
        collect.assert_not_called()

    def test_email_contains_body_and_attachment_for_same_account(self):
        smtp = Mock()
        with patch.object(monitor.smtplib, 'SMTP', return_value=smtp), \
             patch.object(monitor, 'collect_report', return_value=self.report):
            result = monitor.smtp_action(self.config, 90)
        msg = smtp.send_message.call_args.args[0]
        self.assertEqual(msg['To'], self.config['email'])
        self.assertEqual(msg['From'], self.config['email'])
        self.assertEqual(msg['Subject'], 'Station 2 - Idle Check Report')
        self.assertIn('example.exe', msg.get_body(preferencelist=('plain',)).get_content())
        attachment = list(msg.iter_attachments())[0]
        self.assertEqual(attachment.get_filename(), 'idle-application-report.txt')
        self.assertIn(reports.UNKNOWN, attachment.get_content())
        self.assertEqual(result, self.report)

    def test_email_applies_whitelist_to_body_and_attachment(self):
        smtp = Mock()
        self.config['app_whitelist'] = ['example.exe']
        with patch.object(monitor.smtplib, 'SMTP', return_value=smtp), \
             patch.object(reports, 'open_windows', return_value=[row()]), \
             patch.object(reports, 'office_status', return_value=[]):
            report = monitor.smtp_action(self.config, 90)
        self.assertEqual(report['windows'], [])
        msg = smtp.send_message.call_args.args[0]
        self.assertNotIn('Example document', msg.get_body(preferencelist=('plain',)).get_content())
        self.assertNotIn('example.exe', list(msg.iter_attachments())[0].get_content())

    def test_rejection_does_not_collect_or_send(self):
        smtp = Mock()
        smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b'rejected')
        with patch.object(monitor.smtplib, 'SMTP', return_value=smtp), \
             patch.object(monitor, 'collect_report') as collect:
            with self.assertRaises(smtplib.SMTPAuthenticationError): monitor.smtp_action(self.config, 90)
        collect.assert_not_called()
        smtp.send_message.assert_not_called()

    def test_archive_and_archive_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            monitor.save_email_report(folder, self.report)
            self.assertIn('example.exe', (folder / 'latest-email-report.txt').read_text(encoding='utf-8'))
            with patch.object(monitor.os, 'replace', side_effect=OSError('denied')):
                monitor.save_email_report(folder, self.report)
            self.assertFalse(list(folder.glob('report-*.tmp')))


if __name__ == '__main__':
    unittest.main()
