.PHONY: dev

.ONESHELL:
SHELL := /bin/bash

dev:
	@echo "Starting development environment..."
	@mkdir -p ./internals/server/assets/css ./internals/server/assets/static
	@test -f ./internals/server/assets/css/input.css || printf '@import "tailwindcss";\n@plugin "daisyui";\n' > ./internals/server/assets/css/input.css
	@trap 'kill $$(jobs -p) 2>/dev/null || true' EXIT INT TERM
	@npx @tailwindcss/cli -i ./internals/server/assets/css/input.css -o ./internals/server/assets/static/output.css --watch &
	@templ generate --watch &
	@air