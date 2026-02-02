# CloudSentry API Examples

## Authentication
Currently, CloudSentry Phase 1 has no authentication. In production, add API keys or OAuth.

## Base URL
http://localhost:8000/api/v1

## Finding Management

### List Findings
```bash
curl "http://localhost:8000/api/v1/findings?severity=HIGH&limit=10"
```

### Get Finding by ID
```bash
curl "http://localhost:8000/api/v1/findings/{finding_id}"
```

### Update Finding Status
```bash
curl -X PUT "http://localhost:8000/api/v1/findings/{finding_id}" \
  -H "Content-Type: application/json" \
  -d '{"status": "RESOLVED"}'
```

### Get Summary Statistics
```bash
curl "http://localhost:8000/api/v1/findings/stats/summary?time_range=7d"
```

## Rule Management

### List All Rules
```bash
curl "http://localhost:8000/api/v1/rules"
```

### Enable/Disable Rule
```bash
curl -X PUT "http://localhost:8000/api/v1/rules/S3-001" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

## Audit Management

### Trigger Manual Audit
```bash
curl -X POST "http://localhost:8000/api/v1/audits/trigger?audit_type=full"
```

### Get Audit History
```bash
curl "http://localhost:8000/api/v1/audits?limit=5"
```

## WebSocket Real-time Stream

### Connect to WebSocket
```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('New finding:', data);
};

// Send ping to test connection
ws.send(JSON.stringify({ type: 'ping' }));
```

### WebSocket Message Format
```json
{
  "type": "finding",
  "rule_id": "S3-001",
  "resource_id": "test-bucket-123",
  "severity": "HIGH",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

## Filtering Examples

### By Time Range
```
/findings?start_date=2024-01-01T00:00:00Z&end_date=2024-01-15T23:59:59Z
```

### By Multiple Criteria
```
/findings?severity=HIGH&resource_type=s3&account_id=123456789012
```

### Search by Resource ID
```
/findings?search=production
```

## Response Codes
- **200**: Success
- **400**: Bad request (invalid parameters)
- **404**: Resource not found
- **500**: Internal server error
