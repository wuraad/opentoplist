PYTHON ?= python

.PHONY: test run fmt

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

run:
	$(PYTHON) -m backend.app.api_server

loadtest:
	$(PYTHON) tests/load_test_stub.py http://127.0.0.1:8080 200
