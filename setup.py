from setuptools import setup, find_packages
import sys

extra = {}
if sys.version_info >= (3,):
    extra['use_2to3'] = True

setup(name="python-smpplib",
      version='1.0.1',
      url='https://github.com/podshumok/python-smpplib',
      description='SMPP library for python',
      packages=find_packages(),
      zip_safe=True,
      classifiers=[
        'Development Status :: 1 - Alp',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Topic :: Communications :: Telephony',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved',
        ],
      **extra
)
