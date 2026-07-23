.PHONY: all build css dev
all: build
.ONESHELL:
SHELL := /bin/bash

dev: css
	@test -f ./assets/css/input.css || printf '@import "tailwindcss";\n@plugin "daisyui";\n' > ./assets/css/input.css
	@trap 'kill $$(jobs -p) 2>/dev/null || true' EXIT INT TERM
	@npx @tailwindcss/cli -i ./assets/css/input.css -o ./assets/static/output.css --watch &
	@templ generate --watch &
	@air

css: ./assets/css/input.css
	@mkdir -p ./assets/static
	npx @tailwindcss/cli -i ./assets/css/input.css -o ./assets/static/output.css

build: css
	@echo "[*] Building server binary"
	go build -o server .

#  assets directory generation
./assets/css/input.css:
	@echo "[*] Generating CSS assets"
	@mkdir -p ./assets/css
	@printf '@import "tailwindcss";\n@plugin "daisyui";\n' > ./assets/css/input.css
