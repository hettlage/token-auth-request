import os
import codecs
from setuptools import setup


def read(fname):
    file_path = os.path.join(os.path.dirname(__file__), fname)
    return codecs.open(file_path, encoding='utf-8').read()


setup(
    name="token_auth_request",
    version="0.1.0",
    author='SALT/SAAO',
    author_email='salthelp@salt.ac.za',
    maintainer='SALT/SAAO',
    maintainer_email='salthelp@salt.ac.za',
    license='MIT',
    url='https://github.com/saltastro/pytest-db-content',
    description='A plugin for using pytest with a database',
    long_description=read('README.rst'),
    py_modules=['token_auth_request'],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    install_requires=['requests'],
    tests_require=['pytest', 'httpretty'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Pytest',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Testing',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: MIT License',
    ],
)
