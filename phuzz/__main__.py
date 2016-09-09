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

    server.stop()
    return ret


def _parse_options():
    parser = argparse.ArgumentParser(description='PHP Hardening Phuzzer')
    parser.add_argument(
        '-t', '--root', type=str, help='Document root', default=os.getcwd())
    parser.add_argument(
        '-p', '--port', type=int, help='HTTP Server listen port',
        nargs=1, default=randint(8192, 50000))
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
