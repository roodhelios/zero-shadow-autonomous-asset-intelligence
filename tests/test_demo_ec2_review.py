import json
import os
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from engine.demo_ec2_review import main


@unittest.skipUnless(os.name == 'posix', 'private receipts require POSIX')
class EC2ReviewExerciseTests(unittest.TestCase):
    def test_complete_exercise_without_network_or_private_stdout(self):
        output = StringIO()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), redirect_stdout(output):
            self.assertEqual(main(), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'ec2_review_exercise_passed')
        self.assertEqual(result['changed'], 1)
        self.assertEqual(result['changed_export'], 'rejected')
        self.assertTrue(result['original_discovery_removed'])
        self.assertTrue(result['inputs_unchanged'])
        for private in ('111122223333', '192.0.2.40', 'cloud-platform', 'synthetic-ec2-review'):
            self.assertNotIn(private, output.getvalue())


if __name__ == '__main__': unittest.main()
