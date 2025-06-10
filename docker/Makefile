# Makefile for GoVPN Docker Environment

.PHONY: help build up down restart logs shell clean certs test health

# Default target
help: ## Show this help message
	@echo "GoVPN Docker Environment"
	@echo "========================"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build and startup
build: ## Build GoVPN server image
	@echo "Building GoVPN server image..."
	docker-compose build govpn-server

up: ## Start all services
	@echo "Starting all services..."
	docker-compose up -d
	@echo "Services started. Use 'make logs' to see logs."
	@echo ""
	@echo "Access points:"
	@echo "  Keycloak Admin: http://localhost:8080 (admin/admin123)"
	@echo "  GoVPN API:      http://localhost:8081"
	@echo "  Grafana:        http://localhost:3000 (admin/admin123)"
	@echo "  Prometheus:     http://localhost:9091"

down: ## Stop all services
	@echo "Stopping all services..."
	docker-compose down

restart: ## Restart all services
	@echo "Restarting all services..."
	docker-compose restart

rebuild: down build up ## Rebuild and restart all services

# Monitoring and debugging
logs: ## Show logs for all services
	docker-compose logs -f

logs-govpn: ## Show logs for GoVPN server only
	docker-compose logs -f govpn-server

logs-keycloak: ## Show logs for Keycloak only
	docker-compose logs -f keycloak

shell: ## Get shell access to GoVPN container
	docker exec -it govpn-server sh

shell-keycloak: ## Get shell access to Keycloak container
	docker exec -it govpn-keycloak bash

# Certificates and configuration
certs: ## Generate client certificates
	@echo "Generating client certificates..."
	docker exec -it govpn-server /usr/local/bin/generate-certs.sh
	@echo "Copying client configuration..."
	docker cp govpn-server:/etc/govpn/certs/client-bundle.ovpn ./client-bundle.ovpn
	@echo "Client configuration saved to: ./client-bundle.ovpn"

oidc-config: ## Generate OIDC client configuration
	@echo "Generating OIDC client configuration..."
	docker exec -it govpn-server /usr/local/bin/generate-oidc-client.sh
	@echo "Copying OIDC client configurations..."
	docker cp govpn-server:/var/lib/govpn/tunnelblick-oidc.ovpn ./tunnelblick-oidc.ovpn
	docker cp govpn-server:/var/lib/govpn/oidc-client-simple.ovpn ./oidc-client-simple.ovpn
	docker cp govpn-server:/var/lib/govpn/client-auth.txt ./client-auth.txt
	@echo ""
	@echo "✅ OIDC client configurations generated:"
	@echo "   📁 tunnelblick-oidc.ovpn    - For Tunnelblick (macOS)"
	@echo "   📁 oidc-client-simple.ovpn  - Simple OIDC config"
	@echo "   📁 client-auth.txt          - Test credentials (testuser/password123)"
	@echo ""
	@echo "🚀 Import tunnelblick-oidc.ovpn into Tunnelblick and connect!"

certs-copy: ## Copy certificates from container
	@echo "Copying certificates from container..."
	docker cp govpn-server:/etc/govpn/certs ./certs-backup
	@echo "Certificates copied to: ./certs-backup/"

config-copy: ## Copy configuration from container
	@echo "Copying configuration from container..."
	docker cp govpn-server:/etc/govpn ./config-backup
	@echo "Configuration copied to: ./config-backup/"

# Health checks and testing
health: ## Check health of all services
	@echo "Checking service health..."
	@echo ""
	@echo "GoVPN Server:"
	@curl -s http://localhost:8081/health || echo "  ❌ GoVPN API not responding"
	@echo ""
	@echo "Keycloak:"
	@curl -s http://localhost:8080/health || echo "  ❌ Keycloak not responding"
	@echo ""
	@echo "Prometheus:"
	@curl -s http://localhost:9091/-/healthy || echo "  ❌ Prometheus not responding"
	@echo ""
	@echo "Grafana:"
	@curl -s http://localhost:3000/api/health || echo "  ❌ Grafana not responding"

test: ## Run basic connectivity tests
	@echo "Running connectivity tests..."
	@echo ""
	@echo "Testing OIDC discovery:"
	@curl -s http://localhost:8080/realms/govpn/.well-known/openid_configuration | jq -r '.issuer' || echo "❌ OIDC discovery failed"
	@echo ""
	@echo "Testing GoVPN metrics:"
	@curl -s http://localhost:9090/metrics | grep -c govpn || echo "❌ GoVPN metrics not found"
	@echo ""
	@echo "Testing network connectivity:"
	@docker exec govpn-server ping -c 3 keycloak || echo "❌ Cannot reach Keycloak from GoVPN"

test-auth: ## Test OIDC authentication flow
	@echo "Testing OIDC authentication..."
	@echo "This will open browser for manual testing..."
	@open "http://localhost:8080/realms/govpn/account/" || echo "Please open: http://localhost:8080/realms/govpn/account/"

# Status and information
status: ## Show status of all containers
	docker-compose ps

stats: ## Show resource usage statistics
	docker stats

info: ## Show detailed information about the setup
	@echo "GoVPN Docker Environment Information"
	@echo "===================================="
	@echo ""
	@echo "Container Status:"
	@docker-compose ps --format table
	@echo ""
	@echo "Network Information:"
	@docker network ls | grep govpn
	@echo ""
	@echo "Volume Information:"
	@docker volume ls | grep govpn
	@echo ""
	@echo "Access URLs:"
	@echo "  Keycloak Admin:    http://localhost:8080"
	@echo "  GoVPN API:         http://localhost:8081"
	@echo "  GoVPN Metrics:     http://localhost:9090" 
	@echo "  Prometheus:        http://localhost:9091"
	@echo "  Grafana:           http://localhost:3000"
	@echo "  Nginx Proxy:       http://localhost:80"
	@echo ""
	@echo "VPN Connection:"
	@echo "  Server:            localhost:1194"
	@echo "  Protocol:          UDP"
	@echo "  Network:           10.8.0.0/24"

# Cleanup
clean: ## Remove all containers, volumes and images
	@echo "This will remove all GoVPN containers, volumes and images!"
	@read -p "Are you sure? [y/N] " -n 1 -r; echo; if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker-compose down -v --rmi all; \
		docker system prune -f; \
		echo "Cleanup completed."; \
	else \
		echo "Cleanup cancelled."; \
	fi

clean-volumes: ## Remove only volumes (keeps containers)
	@echo "Removing volumes..."
	docker-compose down -v

clean-logs: ## Clear all log files
	@echo "Clearing log files..."
	docker exec govpn-server sh -c "rm -f /var/log/govpn/*.log"
	@echo "Log files cleared."

# Development helpers
dev-setup: build up certs oidc-config ## Complete development setup with OIDC configs
	@echo ""
	@echo "🎉 Development environment ready!"
	@echo ""
	@echo "Available client configurations:"
	@echo "  📁 client-bundle.ovpn       - Standard certificate-based auth"
	@echo "  📁 tunnelblick-oidc.ovpn    - OIDC authentication for Tunnelblick"
	@echo "  📁 oidc-client-simple.ovpn  - Simple OIDC configuration"
	@echo ""
	@echo "Next steps:"
	@echo "1. Import tunnelblick-oidc.ovpn into Tunnelblick for OIDC authentication"
	@echo "2. Connect using credentials: testuser/password123"
	@echo "3. Access web interfaces:"
	@echo "   • Keycloak Admin: http://localhost:8080 (admin/admin123)"
	@echo "   • GoVPN API:      http://localhost:8081"
	@echo "   • Grafana:        http://localhost:3000 (admin/admin123)"
	@echo ""
	@echo "For troubleshooting, use: make logs"

tunnel-test: ## Test VPN tunnel with a simple client
	@echo "Testing VPN tunnel..."
	@if [ -f "./client-bundle.ovpn" ]; then \
		echo "Client configuration found. Testing connection..."; \
		timeout 10s openvpn --config ./client-bundle.ovpn --verb 3 || echo "Connection test completed"; \
	else \
		echo "❌ Client configuration not found. Run 'make certs' first."; \
	fi

# Documentation
docs: ## Generate documentation
	@echo "Opening documentation..."
	@open README.md || echo "Please read README.md for detailed documentation"

# Backup and restore
backup: ## Create backup of all data
	@echo "Creating backup..."
	@mkdir -p backups
	@docker run --rm -v govpn_postgres_data:/data -v $(PWD)/backups:/backup alpine tar czf /backup/postgres-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .
	@docker run --rm -v govpn_govpn_data:/data -v $(PWD)/backups:/backup alpine tar czf /backup/govpn-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .
	@echo "Backup completed in ./backups/"

restore: ## Restore from backup (specify BACKUP_FILE)
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "Usage: make restore BACKUP_FILE=backup-file.tar.gz"; \
		exit 1; \
	fi
	@echo "Restoring from $(BACKUP_FILE)..."
	@docker run --rm -v govpn_postgres_data:/data -v $(PWD)/backups:/backup alpine tar xzf /backup/$(BACKUP_FILE) -C /data
	@echo "Restore completed."

# Performance testing
perf-test: ## Run performance tests
	@echo "Running performance tests..."
	@echo "This requires iperf3 to be installed on the host"
	@docker run --rm --network host governmentpaas/iperf3 -c localhost -p 5201 -t 30 || echo "Performance test completed"

# Quick commands
quick-start: dev-setup ## Alias for dev-setup
restart-govpn: ## Restart only GoVPN server
	docker-compose restart govpn-server

restart-keycloak: ## Restart only Keycloak
	docker-compose restart keycloak 