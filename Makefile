.PHONY: check build secrets compose-config dev-up dev-down integration
check:
	./scripts/check.sh
build:
	./scripts/build.sh
secrets:
	python3 scripts/generate-dev-secrets.py
compose-config:
	./scripts/check-compose.sh
dev-up:
	docker compose -f infra/compose.yaml build
	docker compose -f infra/compose.yaml up -d --wait postgres redis
	docker compose -f infra/compose.yaml run --rm migrate
	docker compose -f infra/compose.yaml up -d --wait device-server gateway
dev-down:
	docker compose -f infra/compose.yaml down
integration:
	./scripts/test-compose.sh
