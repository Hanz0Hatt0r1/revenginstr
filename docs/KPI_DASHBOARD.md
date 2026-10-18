# KPI dashboard

`revenginstr-kpi-dashboard` reads hash-pinned JSON reports and creates a
versioned JSON result plus a Markdown table. The manifest names the KPIs,
JSON Pointers, units, and minimum/maximum targets. It does not hard-code a game,
architecture, label set, or evidence category.

```bash
revenginstr-kpi-dashboard benchmarks/dashboard.json \
  --json-output build/kpi-dashboard.json \
  --markdown-output build/kpi-dashboard.md
```

Each source report must match its declared format and SHA-256. KPI values are
read from RFC 6901 JSON Pointers. Missing or null values are `unavailable` and
make the dashboard `incomplete`; they are never treated as passes. Any failed
target makes the dashboard `fail`. Reports retain source IDs, formats and
hashes but omit source paths and metric row identities. Outputs cannot overwrite
the manifest or a source report.

The manifest contract is
[`KPIDashboardManifest/1`](../schemas/kpi-dashboard-manifest-v1.schema.json);
the JSON output contract is
[`KPIDashboard/1`](../schemas/kpi-dashboard-v1.schema.json). Consumer-owned
manifests and evidence stay in their consumer repositories.
