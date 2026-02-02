#!/bin/bash

# CloudSentry Test Runner Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Default values
TEST_TYPE="all"
COVERAGE="true"
PARALLEL="false"
VERBOSE="false"
MARKERS=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --unit)
            TEST_TYPE="unit"
            shift
            ;;
        --integration)
            TEST_TYPE="integration"
            shift
            ;;
        --api)
            TEST_TYPE="api"
            shift
            ;;
        --security)
            TEST_TYPE="security"
            shift
            ;;
        --no-coverage)
            COVERAGE="false"
            shift
            ;;
        --parallel)
            PARALLEL="true"
            shift
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --markers)
            MARKERS="$2"
            shift 2
            ;;
        --help)
            echo "CloudSentry Test Runner"
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --unit          Run unit tests only"
            echo "  --integration   Run integration tests only"
            echo "  --api           Run API tests only"
            echo "  --security      Run security tests only"
            echo "  --no-coverage   Disable coverage reporting"
            echo "  --parallel      Run tests in parallel"
            echo "  --verbose       Enable verbose output"
            echo "  --markers MARK  Run tests with specific markers"
            echo "  --help          Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --unit                    # Run unit tests only"
            echo "  $0 --integration --parallel  # Run integration tests in parallel"
            echo "  $0 --markers \"slow or database\"  # Run specific test categories"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required"
        exit 1
    fi
    
    # Check pytest
    if ! python3 -m pytest --version &> /dev/null; then
        log_error "pytest is not installed. Install with: pip install -r requirements-test.txt"
        exit 1
    fi
    
    # Check if we're in the right directory
    if [ ! -f "pytest.ini" ] || [ ! -d "tests" ]; then
        log_error "Please run this script from the CloudSentry root directory"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Set test environment variables
    export APP_ENV=test
    export PYTHONPATH="${PYTHONPATH}:$(pwd)"
    
    # Create test directories
    mkdir -p tests/logs
    mkdir -p htmlcov
    
    log_success "Test environment setup complete"
}

# Build pytest command
build_pytest_command() {
    local cmd="python3 -m pytest"
    
    # Add verbosity
    if [ "$VERBOSE" = "true" ]; then
        cmd="$cmd -vv"
    else
        cmd="$cmd -v"
    fi
    
    # Add coverage
    if [ "$COVERAGE" = "true" ]; then
        cmd="$cmd --cov=app --cov-report=term-missing --cov-report=html:htmlcov --cov-report=xml"
    fi
    
    # Add parallel execution
    if [ "$PARALLEL" = "true" ]; then
        cmd="$cmd -n auto"
    fi
    
    # Add test type selection
    case $TEST_TYPE in
        unit)
            cmd="$cmd tests/unit"
            ;;
        integration)
            cmd="$cmd tests/integration"
            ;;
        api)
            cmd="$cmd -m api"
            ;;
        security)
            cmd="$cmd -m security"
            ;;
        all)
            cmd="$cmd tests"
            ;;
    esac
    
    # Add custom markers
    if [ -n "$MARKERS" ]; then
        cmd="$cmd -m \"$MARKERS\""
    fi
    
    # Add timeout
    cmd="$cmd --timeout=300"
    
    echo "$cmd"
}

# Run tests
run_tests() {
    local pytest_cmd=$(build_pytest_command)
    
    log_info "Running tests..."
    log_info "Command: $pytest_cmd"
    echo ""
    
    # Run tests
    if eval $pytest_cmd; then
        log_success "All tests passed!"
        return 0
    else
        log_error "Some tests failed!"
        return 1
    fi
}

# Generate test report
generate_report() {
    if [ "$COVERAGE" = "true" ]; then
        log_info "Generating coverage report..."
        
        if command -v genhtml &> /dev/null; then
            genhtml htmlcov/index.html -o htmlcov/report 2>/dev/null || true
        fi
        
        if [ -f "htmlcov/index.html" ]; then
            log_info "Coverage report available at: htmlcov/index.html"
        fi
        
        if [ -f "coverage.xml" ]; then
            log_info "Coverage XML report generated: coverage.xml"
        fi
    fi
}

# Cleanup test environment
cleanup_test_environment() {
    log_info "Cleaning up test environment..."
    
    # Remove test artifacts
    rm -f .coverage
    rm -f pytest.log
    rm -f .pytest_cache/*
    
    # Keep coverage reports
    log_success "Cleanup complete"
}

# Main execution
main() {
    echo "🧪 CloudSentry Test Runner"
    echo "=========================="
    echo ""
    
    check_prerequisites
    setup_test_environment
    
    start_time=$(date +%s)
    
    if run_tests; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        generate_report
        
        echo ""
        log_success "Test suite completed successfully in ${duration}s!"
        
        if [ "$COVERAGE" = "true" ] && [ -f "htmlcov/index.html" ]; then
            echo "📊 Coverage report: file://$(pwd)/htmlcov/index.html"
        fi
    else
        log_error "Test suite failed!"
        cleanup_test_environment
        exit 1
    fi
    
    cleanup_test_environment
}

# Handle script interruption
trap 'log_error "Test run interrupted"; cleanup_test_environment; exit 1' INT TERM

# Run main function
main "$@"
