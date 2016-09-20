#!/usr/bin/env python

import argparse
import os
import sys
from nose.core import run
from nose_htmloutput import HtmlOutput


def main():
    description = ("Runs footmark unit and/or integration tests. "
                   "Arguments will be passed on to nosetests. "
                   "See nosetests --help for more information.")
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-t', '--service-tests', action="append", default=[],
                        help="Run tests for a given service.  This will "
                        "run any test tagged with the specified value, "
                        "e.g -t ecs -t oss")
    known_args, remaining_args = parser.parse_known_args()
    attribute_args = []
    if not attribute_args:
        # If the user did not specify any filtering criteria, we at least
        # will filter out any test tagged 'notdefault'.
        attribute_args = ['-v','--with-html', '--html-file=result.html']

    # Set default tests used by e.g. tox. For Py2 this means all unit
    # tests, while for Py3 it's just whitelisted ones.
    if 'default' in remaining_args:
        # Run from the base project directory
        os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        for i, arg in enumerate(remaining_args):
            if arg == 'default':
                remaining_args[i] = 'tests/unit'

    all_args = [__file__] + attribute_args + remaining_args
    print("nose command:", ' '.join(all_args))

    run(argv=all_args, plugins=[HtmlOutput()])

if __name__ == "__main__":
    sys.exit(main())
