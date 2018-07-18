"""Packaging script for https://github.com/rambo/python-fanuc-serialbuffer"""
import os
import subprocess
import sys

import setuptools

if sys.version_info < (3, 5):
    raise RuntimeError("Minimum version python 3.5")

GIT_VERSION = 'UNKNOWN'
try:
    GIT_VERSION = subprocess.check_output(['git', 'rev-parse', '--verify', '--short', 'HEAD']).decode('ascii').strip()
except subprocess.CalledProcessError:
    pass

setuptools.setup(
    name='fanucserial',
    version=os.getenv('PACKAGE_VERSION', '0.1.0+git.%s' % GIT_VERSION),
    author='Eero "rambo" af Heurlin',
    author_email='rambo@iki.fi',
    packages=setuptools.find_packages(),
    license='MIT',
    long_description=open('README.md', 'rt', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    description='Implement Fanuc Series 0 remote buffer protocols',
    install_requires=open('requirements.txt', 'rt', encoding='utf-8').readlines(),
    url='https://github.com/rambo/python-fanuc-serialbuffer',
    classifiers=(
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3 :: Only",
    ),
)
