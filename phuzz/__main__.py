from __future__ import print_function
import argparse
import os
import logging
import sys
from random import randint
from . import PHPHarness, Analyzer

LOG = logging.getLogger(__name__)


def main(options):
    logging.basicConfig(level=options.loglevel)
    port = options.port
    root = os.getcwd()
    self_file = os.path.abspath(sys.modules['__main__'].__file__)
    preload = os.path.join(os.path.dirname(self_file), '_preload.php')
    ret = 0

    server = PHPHarness(('127.0.0.1', str(port)), root, preload)
    server.start()

    worker = Analyzer(server)
    stop = False
    try:
        if options.files:
            for filename in options.files:
                worker.run_file(os.path.realpath(filename))
        else:
            # Otherwise traverse document root for files to scan
            for path, _, files in os.walk(root):
                php_files = filter(lambda X: os.path.splitext(X)[1] == '.php',
                                   sorted(files))
                for filename in php_files:
                    try:
                        worker.run_file(os.path.join(path, filename))
                    except KeyboardInterrupt:
                        stop = True
                        break
                if stop:
                    break
    except Exception:
        ret = 1
        LOG.exception("FAIL...")

    if options.wait:
        print("Waiting at http://" + ':'.join(server.listen))
        try:
            server.proc.wait()
        except KeyboardInterrupt:
            pass

    server.stop()
    return ret


def _parse_options():
    cwd = os.getcwd()
    parser = argparse.ArgumentParser(description='PHP Hardening Phuzzer')
    parser.add_argument(
        'files', help='Specific files to fuzz', nargs='*')
    parser.add_argument(
        '-t', '--root', type=str, help='Document root (default: cwd)', default=cwd)
    parser.add_argument(
        '-p', '--port', type=int, help='HTTP listen port',
        nargs=1, default=randint(8192, 50000))
    parser.add_argument(
        '-w', '--wait',
        help="Keep the server running after automatic testing",
        action="store_true", dest="wait", default=False,
    )
    parser.add_argument(
        '-d', '--debug',
        help="Print lots of debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        '-v', '--verbose',
        help="Be verbose, display INFO and NOTICE etc.",
        action="store_const", dest="loglevel", const=logging.INFO,
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main(_parse_options()))
