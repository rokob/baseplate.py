PYTHON_SOURCE = $(shell find baseplate/ tests/ -name '*.py')
PYTHON_EXAMPLES = $(shell find docs/ -name '*.py')

all: thrift

THRIFT=thrift
THRIFT_OPTS=-strict -gen py:slots
THRIFT_BUILDDIR=build/thrift
THRIFT_SOURCE=baseplate/thrift/baseplate.thrift tests/integration/test.thrift
THRIFT_BUILDSTAMPS=$(patsubst %,$(THRIFT_BUILDDIR)/%_buildstamp,$(THRIFT_SOURCE))

thrift: $(THRIFT_BUILDSTAMPS)

# we use a python namespace which causes a whole bunch of extra nested
# directories that we want to get rid of
$(THRIFT_BUILDDIR)/baseplate/thrift/baseplate.thrift_buildstamp: baseplate/thrift/baseplate.thrift
	mkdir -p $(THRIFT_BUILDDIR)/$<
	$(THRIFT) $(THRIFT_OPTS) -out $(THRIFT_BUILDDIR)/$< $<
	cp -r $(THRIFT_BUILDDIR)/$</baseplate/thrift baseplate/
	rm -f baseplate/thrift/BaseplateService-remote
	rm -f baseplate/thrift/BaseplateServiceV2-remote
	touch $@

$(THRIFT_BUILDDIR)/tests/integration/test.thrift_buildstamp: tests/integration/test.thrift
	mkdir -p $(THRIFT_BUILDDIR)/$<
	$(THRIFT) $(THRIFT_OPTS) -out $(THRIFT_BUILDDIR)/$< $<
	cp $(THRIFT_BUILDDIR)/$</test/* tests/integration/test_thrift
	rm -f tests/integration/test_thrift/TestService-remote
	touch $@

.venv: pyproject.toml poetry.lock
	poetry install --all-extras

.PHONY: docs
docs: .venv
	.venv/bin/sphinx-build -M html docs/ build/

.PHONY: doctest
doctest: .venv
	.venv/bin/sphinx-build -M doctest docs/ build/

.PHONY: linkcheck
linkcheck: .venv
	.venv/bin/sphinx-build -M linkcheck docs/ build/

.PHONY: test
test: doctest .venv
	# Some files use gevent to monkey patch stdlib functions. This causes problems
	# if it happens after importing the sequential versions of some of these. Thus
	# we need to do it as early as possible.
	.venv/bin/python -m gevent.monkey --module pytest -v tests/

.PHONY: fmt
fmt: .venv
	.venv/bin/ruff check --fix
	.venv/bin/ruff format

.PHONY: lint
lint: .venv
	.venv/bin/ruff check
	.venv/bin/ruff format --check
	PYTHONPATH=. .venv/bin/pylint baseplate/
	.venv/bin/mypy baseplate/

.PHONY: checks
checks: test lint linkcheck

.PHONY: clean
clean:
	-rm -rf build/
	-rm -rf tests/integration/test_thrift/

.PHONY: realclean
realclean: clean
	-rm -rf baseplate.egg-info/
