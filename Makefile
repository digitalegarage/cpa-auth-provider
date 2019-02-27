MOCHA    = node_modules/.bin/_mocha
JSHINT   = jshint
JSDOC    = jsdoc
COVERAGE = istanbul

ifdef VERBOSE
  REPORTER = spec
else
  REPORTER = dot
endif

export NODE_ENV = test

all: lint coverage

test:
	@$(MOCHA) --bail --timeout 10000 --exit --reporter $(REPORTER) --require test/test-helper test/lib test/api test/api/v2/user test/oauth

lint: lint-src lint-test

lint-src:
	@$(JSHINT) bin/* lib/*.js routes/*

lint-test:
	@$(JSHINT)  --config .jshintrc-test test/*.js test/lib/*.js

coverage:
	@$(COVERAGE) cover $(MOCHA) -- --reporter $(REPORTER) --exit --require test/test-helper test/lib test/api test/api/v2/user test/oauth

doc:
	@$(JSDOC) --private --destination ./docs/ lib models routes routes/auth routes/token routes/user

docs: doc

.PHONY: test lint lint-src lint-test coverage doc docs
