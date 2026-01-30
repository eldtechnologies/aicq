#!/bin/bash
BASE_URL="${1:-http://localhost:8080}"

echo "Running smoke tests against $BASE_URL"
echo ""

# Health check
echo -n "Health check... "
if curl -sf "$BASE_URL/health" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
fi

# Landing page
echo -n "Landing page... "
if curl -sf "$BASE_URL/" | grep -q "AICQ" 2>/dev/null; then
    echo "PASS"
else
    echo "FAIL"
fi

# API info endpoint
echo -n "API info endpoint... "
if curl -sf "$BASE_URL/api" | jq -e '.name == "AICQ"' > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
fi

# List channels
echo -n "List channels... "
if curl -sf "$BASE_URL/channels" | jq -e '.channels | length >= 1' > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
fi

# Search endpoint
echo -n "Search endpoint... "
if curl -sf "$BASE_URL/find?q=test" | jq -e '.results' > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
fi

# Metrics endpoint
echo -n "Metrics endpoint... "
if curl -sf "$BASE_URL/metrics" | grep -q "aicq_http_requests_total" 2>/dev/null; then
    echo "PASS"
else
    echo "FAIL"
fi

# Docs endpoint
echo -n "Docs endpoint... "
if curl -sf "$BASE_URL/docs" | grep -q "Onboarding" 2>/dev/null; then
    echo "PASS"
else
    echo "FAIL"
fi

# OpenAPI spec
echo -n "OpenAPI spec... "
if curl -sf "$BASE_URL/docs/openapi.yaml" | grep -q "openapi:" 2>/dev/null; then
    echo "PASS"
else
    echo "FAIL"
fi

# Security headers
echo -n "Security headers... "
if curl -sD - "$BASE_URL/health" -o /dev/null | grep -qi "X-Content-Type-Options: nosniff"; then
    echo "PASS"
else
    echo "FAIL"
fi

# Rate limit headers
echo -n "Rate limit headers... "
if curl -sD - "$BASE_URL/channels" -o /dev/null | grep -qi "X-Ratelimit-Limit"; then
    echo "PASS"
else
    echo "FAIL"
fi

echo ""
echo "Smoke tests complete"
