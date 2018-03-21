help:
	@echo "  env      install all production dependencies"
	@echo "  dev      install all dev and production dependencies"
	@echo "  info     list info about current environment"
	@echo "  docs     build documentation"
	@echo "  test     run tests"
	@echo "  lint     check style of source code"
	@echo "  build    build the source and wheel."
	@echo "  clean    remove the intermediate python files"

env:
	pip install -Ur requirements.txt

dev: env
	pip2 install -Ur requirements.testing.txt
	pip3 install -Ur requirements.testing.txt
	pip install -Ur requirements.docs.txt
	pip install -U pip setuptools wheel twine keyring tox

info:
	@python --version
	@pip --version

docs:
	$(MAKE) -C docs clean
	$(MAKE) -C docs html

lint:
	pylint fuzzy_extractor/*.py tests/*.py

test:
	python2 -m pytest
	python3 -m pytest

build: test lint
	rm -rf build
	python setup.py sdist bdist_wheel

clean:
	find . -name '*.pyc' -exec rm -f {} \;
	find . -name '*.pyo' -exec rm -f {} \;
