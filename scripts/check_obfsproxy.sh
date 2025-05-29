#!/bin/bash

# GoVPN Obfsproxy Installation Checker
# This script checks if obfsproxy is properly installed and configured

echo "🔍 GoVPN Obfsproxy Installation Checker"
echo "========================================"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to test if binary works
test_binary() {
    local binary="$1"
    local help_flag="$2"
    
    echo -n "   Testing $binary... "
    
    if ! command_exists "$binary"; then
        echo "❌ Not found"
        return 1
    fi
    
    # Test if it responds to help
    if output=$("$binary" "$help_flag" 2>&1); then
        if echo "$output" | grep -q -i "usage\|help\|options"; then
            echo "✅ Working"
            return 0
        fi
    fi
    
    # For obfs4proxy, -help returns error but still shows usage
    if output=$("$binary" "$help_flag" 2>&1) && echo "$output" | grep -q -i "usage"; then
        echo "✅ Working"
        return 0
    fi
    
    echo "⚠️ Found but not responding properly"
    return 1
}

echo ""
echo "🔧 Checking for obfsproxy implementations:"

obfsproxy_found=false
obfs4proxy_found=false

# Check obfsproxy
if test_binary "obfsproxy" "--help"; then
    obfsproxy_found=true
    echo "      Version: $(obfsproxy --version 2>/dev/null || echo 'Unknown')"
fi

# Check obfs4proxy
if test_binary "obfs4proxy" "-help"; then
    obfs4proxy_found=true
    echo "      Version: $(obfs4proxy -version 2>/dev/null || echo 'Unknown')"
fi

echo ""

if $obfsproxy_found || $obfs4proxy_found; then
    echo "✅ SUCCESS: Obfsproxy implementation found!"
    
    echo ""
    echo "🧪 Testing with GoVPN:"
    echo "   Run: go test ./pkg/obfuscation/ -v -run TestObfsproxyInstallation"
    echo "   Demo: cd examples && go run obfuscation_demo.go"
    
else
    echo "❌ No obfsproxy implementation found!"
    echo ""
    echo "💡 Installation instructions:"
    echo ""
    
    # Detect OS and provide specific instructions
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "📱 macOS:"
        echo "   brew install obfs4proxy"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "🐧 Ubuntu/Debian:"
            echo "   sudo apt-get update"
            echo "   sudo apt-get install obfsproxy"
            echo "   # or"
            echo "   sudo apt-get install obfs4proxy"
        elif command_exists yum; then
            echo "🐧 CentOS/RHEL:"
            echo "   sudo yum install obfsproxy"
        elif command_exists dnf; then
            echo "🐧 Fedora:"
            echo "   sudo dnf install obfsproxy"
        else
            echo "🐧 Linux:"
            echo "   Use your package manager to install obfsproxy or obfs4proxy"
        fi
    fi
    
    echo ""
    echo "🐍 Python (universal):"
    echo "   pip install obfsproxy"
    echo ""
    echo "🔧 From source:"
    echo "   go install gitlab.com/yawning/obfs4.git/obfs4proxy@latest"
fi

echo ""
echo "📚 Documentation:"
echo "   - examples/OBFSPROXY_USAGE.md"
echo "   - docs/TESTING_OBFSPROXY.md"
echo "   - examples/obfsproxy_config.json"

exit 0 