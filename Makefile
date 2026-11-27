SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down run test bench lint

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

lint:
	python3 -m py_compile src/eol_tracker/app.py internal/webhook/auth.py internal/policy/opa.py internal/awseol/collector.py tests/test_eol_tracker.py

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	EOL_BUCKET=aws-eol-tracker-reports \
	WEBHOOK_HMAC_SECRET=local-dev-eol-secret \
	uvicorn src.eol_tracker.app:app --host 0.0.0.0 --port 8080

test:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	EOL_BUCKET=aws-eol-tracker-reports \
	WEBHOOK_HMAC_SECRET=local-dev-eol-secret \
	python3 -m unittest discover -s tests -p "test_*.py" -v

bench:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	EOL_BUCKET=aws-eol-tracker-reports \
	WEBHOOK_HMAC_SECRET=local-dev-eol-secret \
	python3 -m unittest tests/test_eol_tracker.py -k bench -v
