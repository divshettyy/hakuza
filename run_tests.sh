#!/bin/bash
# HAKUZA Comprehensive Test Suite - Test Runner
# Executes all test categories with reporting

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}HAKUZA Comprehensive Test Suite${NC}"
echo -e "${BLUE}================================${NC}"
echo

# Test categories
CATEGORIES=(
    "unit"
    "integration"
    "performance"
    "security"
    "regression"
    "stress"
    "chaos"
    "compatibility"
    "e2e"
    "mutation"
)

# Configuration
COVERAGE_THRESHOLD=85
TIMEOUT=600
WORKERS=4

# Function to print usage
usage() {
    echo "Usage: $0 [OPTION]"
    echo "Options:"
    echo "  -a, --all          Run all test categories"
    echo "  -c, --category     Run specific category (unit|integration|performance|security|regression|stress|chaos|compatibility|e2e|mutation)"
    echo "  -q, --quick        Run quick tests only (skip stress/performance)"
    echo "  --coverage         Generate coverage report"
    echo "  --parallel         Run tests in parallel"
    echo "  --verbose          Verbose output"
    echo "  -h, --help         Show this help message"
    exit 0
}

# Function to run tests
run_tests() {
    local category=$1
    local markers=$2
    local verbose=$3

    echo -e "${YELLOW}Running ${category} tests...${NC}"

    if [ "$verbose" = "true" ]; then
        pytest test_comprehensive.py -v -m "$markers" \
            --timeout=$TIMEOUT \
            --tb=short \
            --color=yes
    else
        pytest test_comprehensive.py -m "$markers" \
            --timeout=$TIMEOUT \
            --tb=line \
            --color=yes \
            -q
    fi
}

# Function to run all tests with coverage
run_all_with_coverage() {
    echo -e "${YELLOW}Running all tests with coverage...${NC}"

    pytest test_comprehensive.py \
        --cov=. \
        --cov-report=html:htmlcov \
        --cov-report=xml:coverage.xml \
        --cov-report=term-missing:skip-covered \
        --cov-report=json:coverage.json \
        --timeout=$TIMEOUT \
        --junitxml=test-results.xml \
        --html=test-report.html \
        --self-contained-html \
        -v

    # Check coverage threshold
    COVERAGE=$(grep -oP '"percent_covered": \K[^,]+' coverage.json | head -1)
    echo -e "${BLUE}Coverage: ${COVERAGE}%${NC}"

    if (( $(echo "$COVERAGE < $COVERAGE_THRESHOLD" | bc -l) )); then
        echo -e "${RED}Coverage ${COVERAGE}% is below threshold ${COVERAGE_THRESHOLD}%${NC}"
        exit 1
    fi
}

# Function to run quick tests
run_quick() {
    echo -e "${YELLOW}Running quick tests...${NC}"

    pytest test_comprehensive.py \
        -m "not stress and not performance" \
        --timeout=60 \
        -v \
        --tb=short
}

# Function to run tests in parallel
run_parallel() {
    echo -e "${YELLOW}Running tests in parallel (${WORKERS} workers)...${NC}"

    pytest test_comprehensive.py \
        -n $WORKERS \
        --timeout=$TIMEOUT \
        --tb=short \
        -v
}

# Main execution
if [ $# -eq 0 ]; then
    run_all_with_coverage
else
    case "$1" in
        -a|--all)
            run_all_with_coverage
            ;;
        -c|--category)
            if [ $# -lt 2 ]; then
                echo "Error: --category requires an argument"
                usage
            fi
            category=$2
            run_tests "$category" "$category" "false"
            ;;
        -q|--quick)
            run_quick
            ;;
        --coverage)
            run_all_with_coverage
            ;;
        --parallel)
            run_parallel
            ;;
        --verbose)
            run_all_with_coverage
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
fi

echo
echo -e "${GREEN}Test execution completed${NC}"
