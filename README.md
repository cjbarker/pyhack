# PY-HACK

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
* [PORTSCAN](./pyhack/portscan): Multi-threaded port scanner leveraging [NMAP](https://nmap.org/)
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
```

## References
* [NMAP](https://nmap.org/) network discovery and security auditing
