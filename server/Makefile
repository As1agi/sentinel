.PHONY:	build css dev

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
	npx @tailwindcss/cli -i ./assets/css/input.css -o ./assets/static/output.css 1>/dev/null

# todo generate separate assets for the build 
build: css
	@echo "[*] Building server binary"
	@mkdir -p build  
#copy the assets and scripts into the build directory
	@cp ./assets -r build/assets 
	@cp scripts -r build/scripts 

	go build -o build/server .

#  assets directory generation
./assets/css/input.css:
	@echo "[*] Generating CSS assets"
	@mkdir -p ./assets/css
	@printf '@import "tailwindcss";\n@plugin "daisyui";\n' > ./assets/css/input.css 
