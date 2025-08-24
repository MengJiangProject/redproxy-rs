# RedProxy Sanity Tests Makefile

.PHONY: test test-verbose clean build logs help

# Default target
test: 
	@echo "Running RedProxy sanity tests..."
	docker-compose up --build --abort-on-container-exit --remove-orphans

# Run tests with verbose output
test-verbose:
	@echo "Running RedProxy sanity tests with verbose logging..."
	docker-compose up --build --abort-on-container-exit --remove-orphans -d
	docker-compose logs -f

# Build containers without running tests
build:
	@echo "Building test containers..."
	docker-compose build

# Clean up containers and volumes
clean:
	@echo "Cleaning up test environment..."
	docker-compose down -v --remove-orphans
	docker system prune -f

# Show logs from last run
logs:
	docker-compose logs

# Show available targets
help:
	@echo "Available targets:"
	@echo "  test         - Run sanity tests (default)"
	@echo "  test-verbose - Run tests with verbose logging"
	@echo "  build        - Build test containers only"
	@echo "  clean        - Clean up containers and volumes"
	@echo "  logs         - Show logs from last run"
	@echo "  help         - Show this help message"