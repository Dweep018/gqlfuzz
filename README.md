# gqlfuzz — GraphQL Unbounded Argument DoS Scanner

Finds GraphQL fields that accept unbounded `Int` arguments (like `limit`, `count`, `size`)
and measures response time and size degradation — the exact class of vulnerability found on
`exchange-api.redacted.local` where `price\_bars(limit: 999999999)` caused a 700ms → 13,000ms slowdown.

\---

## How it works

1. **Introspects** the schema to find all `Int` arguments across every query field
2. **Filters** for limit-like argument names (`limit`, `first`, `last`, `count`, `size`, `take`, etc.)
3. **Establishes a baseline** response time and size with `value=1`
4. **Fuzzes** each argument with escalating values: `100 → 10,000 → 1,000,000 → 999,999,999`
5. **Measures** response time and response size at each level
6. **Flags** any argument where response time grows by 3x or more vs baseline

\---

## Installation

```bash
git clone https://github.com/yourname/gqlfuzz
cd gqlfuzz
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python gqlfuzz.py https://exchange-api.redacted.local/graphql

# Authenticated scan
python gqlfuzz.py https://api.example.com/graphql -t YOUR\_TOKEN

# Custom headers
python gqlfuzz.py https://api.example.com/graphql -H "X-Api-Key: secret"

# Fuzz ALL Int args (not just limit-like ones)
python gqlfuzz.py https://api.example.com/graphql --all-ints

# Lower the detection threshold (flag at 2x slowdown instead of 3x)
python gqlfuzz.py https://api.example.com/graphql --threshold 2.0

# Save JSON report
python gqlfuzz.py https://api.example.com/graphql -o report.json

# Longer timeout for slow endpoints
python gqlfuzz.py https://api.example.com/graphql --timeout 30
```

\---

## Severity Scoring

|Slowdown|Severity|
|-|-|
|Timeout / 15x+|CRITICAL|
|8x – 14x|HIGH|
|3x – 7x|MEDIUM|
|< 3x but large size growth|LOW|

\---

## Output

### Terminal

Live findings printed as each vulnerable argument is confirmed, with:

* Baseline vs worst-case time and size
* Slowdown factor
* The exact query used to reproduce
* Recommended fix

### JSON Report (`-o report.json`)

```json
{
  "scanner": "gqlfuzz",
  "target": "https://exchange-api.redacted.local/graphql",
  "total\_args\_tested": 4,
  "summary": {
    "overall\_risk": "HIGH",
    "vulnerable\_args": 1,
    "by\_severity": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0 }
  },
  "findings": \[
    {
      "field": "instruments.price\_bars.limit",
      "severity": "HIGH",
      "baseline\_time\_ms": 700,
      "worst\_value": 999999999,
      "worst\_time\_ms": 13916,
      "slowdown\_factor": 19.9,
      "query\_used": "{ instruments { price\_bars(limit: 999999999) { \_\_typename } } }",
      "recommendation": "Enforce a hard server-side cap on `limit` (e.g. max 500)..."
    }
  ]
}
```

\---

## Exit Codes

|Code|Meaning|
|-|-|
|`0`|No vulnerable arguments found|
|`1`|HIGH severity found|
|`2`|CRITICAL severity found|

\---

## Real-World Example

This tool directly models the redacted local finding:

```bash
curl -X POST https://exchange-api.redacted.local/graphql \\
  -H "Content-Type: application/json" \\
  --data '{"query":"{ instruments { price\_bars(limit: 999999999) { \_\_typename } } }"}'
# Response time: 13,916ms vs baseline 700ms = 19.9x slowdown
```

The scanner would have caught this automatically by:

1. Discovering `price\_bars` has a `limit: Int` argument via introspection
2. Recognising `limit` as a limit-like argument name
3. Fuzzing it up to `999999999` and measuring the 19.9x slowdown
4. Flagging it as HIGH severity with the reproduction query

\---

## Roadmap

* \[ ] Response time measurement without introspection (blind mode)
* \[ ] String argument fuzzing (oversized strings, repeated chars)
* \[ ] Offset/pagination abuse (offset: 999999999 with limit: 1)
* \[ ] Concurrent request amplification testing
* \[ ] HTML report output

