#!/bin/bash

# Nexus Android App - Build and Installation Script
# This script automates the process of building and installing the APK on an Android device

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Java
    if ! command -v java &> /dev/null; then
        print_error "Java is not installed"
        exit 1
    fi
    print_success "Java found: $(java -version 2>&1 | head -n 1)"
    
    # Check Android SDK
    if [ -z "$ANDROID_SDK_ROOT" ]; then
        print_warning "ANDROID_SDK_ROOT not set. Looking for Android SDK..."
        if [ -d "$HOME/Android/Sdk" ]; then
            export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
            print_success "Android SDK found at $ANDROID_SDK_ROOT"
        else
            print_error "Android SDK not found. Please set ANDROID_SDK_ROOT environment variable."
            exit 1
        fi
    fi
    
    # Check ADB
    if ! command -v adb &> /dev/null; then
        export PATH="$PATH:$ANDROID_SDK_ROOT/platform-tools"
    fi
    
    if ! command -v adb &> /dev/null; then
        print_error "ADB not found. Please ensure Android SDK is properly installed."
        exit 1
    fi
    print_success "ADB found"
    
    echo ""
}

# Clean build
clean_build() {
    print_header "Cleaning Previous Build"
    ./gradlew clean
    print_success "Build cleaned"
    echo ""
}

# Build debug APK
build_debug() {
    print_header "Building Debug APK"
    ./gradlew assembleDebug --info
    if [ $? -eq 0 ]; then
        print_success "Debug APK built successfully"
        echo "Location: app/build/outputs/apk/debug/app-debug.apk"
    else
        print_error "Debug APK build failed"
        exit 1
    fi
    echo ""
}

# Build release APK
build_release() {
    print_header "Building Release APK"
    
    # Check for signing configuration
    if [ -z "$KEYSTORE_FILE" ] || [ -z "$KEYSTORE_PASSWORD" ] || [ -z "$KEY_ALIAS" ] || [ -z "$KEY_PASSWORD" ]; then
        print_warning "Signing credentials not found. Setting up release signing..."
        
        if [ ! -f "$HOME/nexus.keystore" ]; then
            print_header "Generating Keystore"
            keytool -genkey -v -keystore "$HOME/nexus.keystore" \
                -keyalg RSA -keysize 2048 -validity 10000 \
                -alias nexus_key
            print_success "Keystore generated at $HOME/nexus.keystore"
        fi
        
        export KEYSTORE_FILE="$HOME/nexus.keystore"
        read -sp "Enter keystore password: " KEYSTORE_PASSWORD
        export KEYSTORE_PASSWORD
        echo ""
        export KEY_ALIAS="nexus_key"
        read -sp "Enter key password: " KEY_PASSWORD
        export KEY_PASSWORD
        echo ""
    fi
    
    ./gradlew assembleRelease --info
    if [ $? -eq 0 ]; then
        print_success "Release APK built successfully"
        echo "Location: app/build/outputs/apk/release/app-release.apk"
    else
        print_error "Release APK build failed"
        exit 1
    fi
    echo ""
}

# Check connected devices
check_devices() {
    print_header "Checking Connected Devices"
    
    local device_count=$(adb devices | wc -l)
    if [ $device_count -lt 3 ]; then
        print_error "No devices connected. Please connect an Android device via USB and enable USB Debugging."
        exit 1
    fi
    
    adb devices
    print_success "Device(s) found"
    echo ""
}

# Install APK
install_apk() {
    local apk_path=$1
    local apk_name=$(basename "$apk_path")
    
    print_header "Installing $apk_name"
    
    if [ ! -f "$apk_path" ]; then
        print_error "APK file not found at $apk_path"
        exit 1
    fi
    
    adb install -r "$apk_path"
    if [ $? -eq 0 ]; then
        print_success "APK installed successfully"
    else
        print_error "APK installation failed"
        exit 1
    fi
    echo ""
}

# Launch app
launch_app() {
    print_header "Launching App"
    adb shell am start -n com.nexus.app/.MainActivity
    print_success "App launched"
    echo ""
}

# View logs
view_logs() {
    print_header "Application Logs (Press Ctrl+C to stop)"
    echo "Filtering for Nexus app logs..."
    adb logcat | grep -E "nexus|Nexus|NEXUS"
}

# Main script logic
main() {
    print_header "Nexus Android App - Build & Installation"
    
    check_prerequisites
    
    # Menu
    echo "Select build type:"
    echo "1) Debug APK (for testing)"
    echo "2) Release APK (for production)"
    echo "3) Full build and install (debug)"
    echo "4) Clean and rebuild"
    echo "5) View app logs"
    echo "6) Uninstall app"
    read -p "Enter choice (1-6): " choice
    
    case $choice in
        1)
            build_debug
            ;;
        2)
            build_release
            ;;
        3)
            check_devices
            build_debug
            install_apk "app/build/outputs/apk/debug/app-debug.apk"
            read -p "Launch app now? (y/n): " launch
            if [ "$launch" = "y" ]; then
                launch_app
            fi
            ;;
        4)
            clean_build
            build_debug
            check_devices
            install_apk "app/build/outputs/apk/debug/app-debug.apk"
            ;;
        5)
            check_devices
            view_logs
            ;;
        6)
            check_devices
            print_header "Uninstalling App"
            adb uninstall com.nexus.app
            print_success "App uninstalled"
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
    
    print_success "Build script completed"
}

# Run main function
main
