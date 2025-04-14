#!/bin/bash

set -e

BASE_URL="http://localhost:8080"
USERNAME="test_user"
PASSWORD="test_pass"

echo -e "\n=== [1] Register new user ==="
curl -s -o /dev/null -w "Status: %{http_code}\n" -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}"
echo -e "\n------"

echo -e "\n=== [2] Attempt duplicate registration ==="
curl -s -o /dev/null -w "Status: %{http_code}\n" -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}"
echo -e "\n------"

echo -e "\n=== [3] Login (valid credentials) ==="
response=$(curl -s -w "\nStatus: %{http_code}\n" -X POST "$BASE_URL/login" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
echo "$response"
echo -e "\n------"

access_token=$(echo "$response" | grep -oP '(?<="access_token":")[^"]+')
refresh_token=$(echo "$response" | grep -oP '(?<="refresh_token":")[^"]+')

echo -e "\nAccess Token:\n$access_token"
echo -e "\nRefresh Token:\n$refresh_token"
echo -e "\n------"

echo -e "\n=== [4] Login (invalid password) ==="
curl -s -o /dev/null -w "Status: %{http_code}\n" -X POST "$BASE_URL/login" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"wrongpass\"}"
echo -e "\n------"

echo -e "\n=== [5] Access secure data with valid access token ==="
curl -s -w "\nStatus: %{http_code}\n" -X GET "$BASE_URL/secure/data" \
     -H "Authorization: Bearer $access_token"
echo -e "\n------"

echo -e "\n=== [6] Access secure data WITHOUT token ==="
curl -s -w "\nStatus: %{http_code}\n" -X GET "$BASE_URL/secure/data"
echo -e "\n------"

echo -e "\n=== [7] Refresh access token ==="
new_access=$(curl -s -w "\nStatus: %{http_code}\n" -X POST "$BASE_URL/refresh" \
     -H "Authorization: Bearer $refresh_token" \
     -H "Content-Type: application/json" \
     -d '{}' | tee /tmp/refresh_response.json | grep -oP '(?<="access_token":")[^"]+')

echo -e "\nNew Access Token:\n$new_access"
echo -e "\n------"

echo -e "\n=== [8] Refresh with invalid token ==="
curl -s -w "\nStatus: %{http_code}\n" -X POST "$BASE_URL/refresh" \
     -H "Authorization: Bearer invalid.token.value" \
     -H "Content-Type: application/json" \
     -d '{}'
echo -e "\n------"

echo -e "\n=== [9] Logout user (blacklist refresh token) ==="
curl -s -w "\nStatus: %{http_code}\n" -X POST "$BASE_URL/logout" \
     -H "Authorization: Bearer $refresh_token" \
     -H "Content-Type: application/json" \
     -d '{}'
echo -e "\n------"

echo -e "\n=== [10] Attempt to refresh after logout ==="
curl -s -w "\nStatus: %{http_code}\n" -X POST "$BASE_URL/refresh" \
     -H "Authorization: Bearer $refresh_token" \
     -H "Content-Type: application/json" \
     -d '{}'
echo -e "\n------"

echo -e "\n=== [11] Wait 65 seconds for access token to expire ==="
sleep 65
echo -e "\n------"

echo -e "\n=== [12] Access secure data with EXPIRED token ==="
curl -s -w "\nStatus: %{http_code}\n" -X GET "$BASE_URL/secure/data" \
     -H "Authorization: Bearer $access_token"
echo -e "\n------"

echo -e "\nТестирование завершено."
