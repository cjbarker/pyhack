# PY-HACK

[![pipeline status](https://gitlab.com/cjbarker/pyhack/badges/master/pipeline.svg)](https://gitlab.com/cjbarker/pyhack/commits/master)
[![coverage report](https://gitlab.com/cjbarker/pyhack/badges/master/coverage.svg)](https://cjbarker.gitlab.io/pyhack/)
[![Read the Docs](https://img.shields.io/readthedocs/pip.svg)](https://cjbarker.gitlab.io/pyhack/docs/)
[![GitLab license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://gitlab.com/cjbarker/pyhack/blob/master/LICENSE)

A collection of white-hat custom security tools used for education and ethical testing in a controlled environment.

## Install
```bash
# Rereq setuptools
pip install setuptools
```

Create source distriuption package and eggo-info
```bash
python setup.py sdist

.
├── dist
│   └── pyhack-0.0.1.tar.gz
├── pyhack.egg-info
│   ├── PKG-INFO
│   ├── SOURCES.txt
│   ├── dependency_links.txt
│   └── top_level.txt
└── setup.py
```

## Tools
* [PORTSCAN](./pyhack/portscan): Multi-threaded port scanner 
* More to come

## Contributing
```bash
pip install futures
pip install --user pipenv
pipenv install nose2
pipenv install pylint
```

## Testing
```bash
# run specific test
pipenv run nose2 -v tests.test_portscan

# run all tests
pipenv run nose2 

# linting
pipenv run pylint pyhack -d C0326 --msg-template='{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}'

# generate docs via Sphinx
cd docs
make clean; make html
```
