import os
import subprocess
import sys
import unittest

from zapret_ui.process_job import ProcessJob


@unittest.skipUnless(os.name == "nt", "Windows Job Object")
class JobTests(unittest.TestCase):
    def test_close_terminates_only_assigned_process(self):
        job = ProcessJob()
        owned = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(45)"], creationflags=subprocess.CREATE_NO_WINDOW)
        unowned = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(45)"], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            job.assign(owned)
            self.assertIsNone(owned.poll())
            job.close()
            self.assertIsNotNone(owned.wait(timeout=5))
            self.assertIsNone(unowned.poll())
        finally:
            job.close()
            for process in (owned, unowned):
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
