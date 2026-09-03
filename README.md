# SOC Threat Intelligence Hash Enricher

A Python CLI tool designed for SOC Analysts to query and enrich file hashes using the Hybrid Analysis API v2.

## Features
- Direct SHA256 overview lookups via Hybrid Analysis REST API.
- Fallback hash searching (supports MD5 / SHA1 / SHA25).
- Secure API Key management using `.env` files.

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/boogyeman228/ProjHybridAnalyst.git](https://github.com/boogyeman228/ProjHybridAnalyst.git)
   cd ProjHybridAnalyst