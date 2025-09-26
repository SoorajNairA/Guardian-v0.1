param(
  [string]$Url = "http://localhost:8000/v1/analyze",
  [string]$ApiKey = "ag_123",
  [int]$DurationSeconds = 30,
  [int]$Rate = 500
)

# Requires hey (https://github.com/rakyll/hey)
hey -z ${DurationSeconds}s -q $Rate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $ApiKey" \
  -m POST \
  -d '{"text":"Click here to reset your password"}' \
  $Url



