import os
import re
import sys

from setuptools import setup

# version is a single quoted ISO 8601 string
version_pattern = re.compile(r"\s*__version__\s*=\s*'([^']+)'")
with open(os.path.join(os.path.dirname(__file__), 'emailproxy.py')) as f:
    for line in f:
        match = version_pattern.match(line)
        if match:
            # convert a "-" and leading 0s to a "."
            version = re.sub(r'-0*', '.', match.group(1))
            break
    else:
        print('Version information could not be found!', file=sys.stderr)
        sys.exit(1)

setup(version=version)
