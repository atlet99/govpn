#!/bin/bash

# GoVPN Development Environment Startup Script
# This script starts both the development API server and web interface

set -e

echo "🚀 Starting GoVPN Development Environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}🛑 Shutting down development servers...${NC}"
    
    # Kill background processes
    if [ ! -z "$API_PID" ]; then
        echo "Stopping API server (PID: $API_PID)"
        kill $API_PID 2>/dev/null || true
    fi
    
    if [ ! -z "$WEB_PID" ]; then
        echo "Stopping web server (PID: $WEB_PID)"
        kill $WEB_PID 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ Development environment stopped${NC}"
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup SIGINT SIGTERM EXIT

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed. Please install Go first.${NC}"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed. Please install Node.js first.${NC}"
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ npm is not installed. Please install npm first.${NC}"
    exit 1
fi

echo -e "${BLUE}📦 Building development API server...${NC}"

# Build the development API server
if go build -o govpn-dev-api ./cmd/dev-api; then
    echo -e "${GREEN}✅ API server built successfully${NC}"
else
    echo -e "${RED}❌ Failed to build API server${NC}"
    exit 1
fi

echo -e "${BLUE}🔧 Installing web dependencies...${NC}"

# Install web dependencies if needed
if [ ! -d "web/node_modules" ]; then
    cd web
    npm install
    cd ..
fi

echo -e "${BLUE}🌐 Starting development API server...${NC}"

# Start the development API server in background
./govpn-dev-api -port 8080 -host 127.0.0.1 &
API_PID=$!

# Wait for API server to start
sleep 3

# Check if API server is running
if curl -s http://localhost:8080/api/v1/status > /dev/null; then
    echo -e "${GREEN}✅ API server started successfully at http://localhost:8080${NC}"
else
    echo -e "${RED}❌ Failed to start API server${NC}"
    exit 1
fi

echo -e "${BLUE}🖥️  Starting web development server...${NC}"

# Start the web development server in background
cd web
npm run dev &
WEB_PID=$!
cd ..

# Wait for web server to start
echo -e "${YELLOW}⏳ Waiting for web server to start...${NC}"
sleep 8

# Check if web server is running
if curl -s http://localhost:5173 > /dev/null; then
    echo -e "${GREEN}✅ Web server started successfully at http://localhost:5173${NC}"
else
    echo -e "${RED}❌ Failed to start web server${NC}"
    exit 1
fi

echo -e "\n${GREEN}🎉 GoVPN Development Environment is ready!${NC}"
echo -e "${BLUE}📍 Web Interface: ${NC}http://localhost:5173"
echo -e "${BLUE}📍 API Server: ${NC}http://localhost:8080/api/v1"
echo -e "\n${YELLOW}Available API endpoints:${NC}"
echo -e "  GET  /api/v1/status        - Server status"
echo -e "  GET  /api/v1/users         - List users"
echo -e "  POST /api/v1/users         - Create user"
echo -e "  GET  /api/v1/clients       - Active connections"
echo -e "  GET  /api/v1/certificates  - Certificates"
echo -e "  GET  /api/v1/config        - Server configuration"
echo -e "  GET  /api/v1/logs          - System logs"

echo -e "\n${YELLOW}💡 Tips:${NC}"
echo -e "  • The web interface is running with hot reload"
echo -e "  • API server provides mock data for development"
echo -e "  • Press Ctrl+C to stop both servers"
echo -e "  • Check browser console for any client-side errors"

# Keep the script running and wait for user interrupt
echo -e "\n${GREEN}🔄 Development servers are running... Press Ctrl+C to stop${NC}\n"

# Keep the script alive
while true; do
    sleep 1
done 