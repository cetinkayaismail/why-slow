# Enterprise Telemetry & SIEM Integration Guide

`why-slow` generates high-resolution, deterministic diagnostic telemetry designed for ingestion into Security Information and Event Management (SIEM), Application Performance Monitoring (APM), and IT Service Management (ITSM) platforms.

---

## 📋 Diagnostic JSON Schema (Draft 2020-12)

When invoked with `--json` (or `--json --compact`), `why-slow` emits a structured payload complying with the following schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "WhySlowDiagnosticReport",
  "type": "object",
  "required": ["timestamp", "privilege_level", "duration"],
  "properties": {
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "UTC ISO-8601 timestamp of diagnostic evaluation"
    },
    "privilege_level": {
      "type": "string",
      "enum": ["root", "unprivileged"]
    },
    "duration": {
      "type": "string",
      "example": "1.00s"
    },
    "system_pressure": {
      "type": "object",
      "properties": {
        "cpu_some_10": { "type": "number" },
        "memory_some_10": { "type": "number" },
        "memory_full_10": { "type": "number" },
        "io_some_10": { "type": "number" },
        "io_full_10": { "type": "number" }
      }
    },
    "primary_blocker": {
      "$ref": "#/$defs/Diagnosis"
    },
    "contributing_factors": {
      "type": "array",
      "items": { "$ref": "#/$defs/Diagnosis" }
    },
    "secondary_issues": {
      "type": "array",
      "items": { "$ref": "#/$defs/Diagnosis" }
    }
  },
  "$defs": {
    "Diagnosis": {
      "type": "object",
      "required": ["rule_id", "severity", "tier", "title", "description", "confidence"],
      "properties": {
        "rule_id": { "type": "string" },
        "severity": { "type": "string", "enum": ["critical", "high", "medium", "info"] },
        "tier": { "type": "integer", "enum": [1, 2, 3] },
        "title": { "type": "string" },
        "description": { "type": "string" },
        "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
        "culprit_pid": { "type": "integer" },
        "culprit_name": { "type": "string" },
        "culprit_metric": { "type": "string" },
        "remediation": { "type": "string" },
        "evidence": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    }
  }
}
```

### Example Machine-Readable Output

```json
{
  "timestamp": "2026-09-02T17:15:00Z",
  "privilege_level": "root",
  "duration": "1.00s",
  "system_pressure": {
    "cpu_some_10": 4.12,
    "memory_some_10": 0.00,
    "memory_full_10": 0.00,
    "io_some_10": 98.40,
    "io_full_10": 92.15
  },
  "primary_blocker": {
    "rule_id": "BASE_DISK_HARDWARE_SATURATION",
    "severity": "critical",
    "tier": 1,
    "title": "Disk Block Device Saturation (nvme0n1)",
    "description": "Storage device 'nvme0n1' is operating at 99.8% utilization capacity over the sampling window.",
    "confidence": 1.0,
    "culprit_pid": 14208,
    "culprit_name": "mysqld",
    "culprit_metric": "580.4 MB write delta during sampling window",
    "remediation": "Lower I/O priority for culprit: ionice -c3 -p 14208",
    "evidence": [
      "Device 'nvme0n1' I/O Utilization: 99.8%",
      "Read Throughput: 0.12 MB/s, Write Throughput: 620.50 MB/s",
      "I/O Operations in Flight: 48"
    ]
  },
  "contributing_factors": [
    {
      "rule_id": "CONT_DSTATE_PILEUP",
      "severity": "high",
      "tier": 2,
      "title": "Uninterruptible I/O Lock (D-State Pileup)",
      "description": "4 active processes blocked in uninterruptible sleep waiting on I/O.",
      "confidence": 0.95,
      "culprit_pid": 14208,
      "culprit_name": "mysqld",
      "culprit_metric": "Waiting on ext4_writepages",
      "remediation": "Investigate underlying storage contention and flush writeback buffers",
      "evidence": [
        "Uninterruptible Sleep Task Count: 4",
        "Common wait channel: ext4_writepages"
      ]
    }
  ],
  "secondary_issues": []
}
```

---

## 📡 Splunk Enterprise & Splunk Cloud Integration

### 1. Ingestion via Universal Forwarder (`inputs.conf`)
```ini
[monitor:///var/log/why-slow/sentinel.json]
sourcetype = why_slow:json
index = infrastructure_diagnostics
disabled = false
```

### 2. Field Extraction & Event Typing (`props.conf`)
```ini
[why_slow:json]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = timestamp
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
KV_MODE = none
AUTO_KV_JSON = true
```

### 3. Production Splunk Alert Search
Query to alert on any Tier 1 Critical Bottleneck across the server fleet:
```spl
index=infrastructure_diagnostics sourcetype="why_slow:json" primary_blocker.tier=1
| stats count by host, primary_blocker.rule_id, primary_blocker.culprit_name, primary_blocker.culprit_pid
| where count >= 1
```

---

## 📊 Elastic SIEM / Logstash Pipeline

### Logstash Pipeline Configuration (`why-slow.conf`)
```ruby
input {
  file {
    path => "/var/log/why-slow/sentinel.json"
    codec => "json"
    type => "why_slow"
  }
}

filter {
  if [type] == "why_slow" {
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch.internal.bank:9200"]
    index => "why-slow-diagnostics-%{+YYYY.MM.dd}"
    ssl => true
    ssl_certificate_verification => true
    cacert => "/etc/ssl/certs/internal-ca.pem"
  }
}
```

---

## 🐶 Datadog Log Forwarding & Metric Pipeline

Configure the Datadog Agent to collect diagnostic events:

### `/etc/datadog-agent/conf.d/why_slow.d/conf.yaml`
```yaml
logs:
  - type: file
    path: /var/log/why-slow/sentinel.json
    service: why-slow
    source: linux-kernel
    sourcecategory: diagnostics
```

---

## 🚀 Vector Sidecar Pipeline (Grafana Loki & Kafka)

High-performance streaming using Vector:

```toml
[sources.why_slow_file]
type = "file"
include = ["/var/log/why-slow/sentinel.json"]
read_from = "beginning"

[transforms.parse_json]
type = "remap"
inputs = ["why_slow_file"]
source = '''
. = parse_json!(.message)
.host = get_hostname!()
'''

[sinks.loki]
type = "loki"
inputs = ["parse_json"]
endpoint = "http://loki:3100"
labels.app = "why-slow"
labels.severity = "{{ primary_blocker.severity }}"
labels.rule_id = "{{ primary_blocker.rule_id }}"
encoding.codec = "json"
```

---

## 🚨 Incident Alert Routing (PagerDuty & Webhooks)

When configuring automated webhook forwarding to **PagerDuty, ServiceNow, or Slack**, format the incident card as follows:

- **Incident Summary**: `[WHY-SLOW] {{ primary_blocker.severity | upper }}: {{ primary_blocker.title }} on {{ host }}`
- **Severity**: `{{ primary_blocker.severity }}`
- **Component**: `Linux Kernel Subsystem`
- **Root Cause**: `{{ primary_blocker.description }}`
- **Culprit Process**: `PID {{ primary_blocker.culprit_pid }} ({{ primary_blocker.culprit_name }})`
- **Immediate Action**: `{{ primary_blocker.remediation }}`
