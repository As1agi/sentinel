.PHONY: dev

dev:
	@echo "Starting development environment..."
	# 1. Run Tailwind compiler in the background
	npx @tailwindcss/cli -i ./internals/server/assets/css/input.css -o ./internals/server/assets/static/output.css --watch & \
	TAILWIND_PID=$$!; \
	# 2. Run Templ generator in the background
	templ generate --watch & \
	TEMPL_PID=$$!; \
	# 3. Run Air in the foreground to anchor the terminal
	air; \
	# Cleanup: Kill background processes when Air exits
	echo "Shutting down proxies and watchers..."; \
    go run ./cmd/cassandra/main.go & \
    SEVER_PID=$$!; \
    kill $$TAILWIND_PID SEVER_PID $$TEMPL_PID 2>/dev/null || true