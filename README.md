# SOC Threat Intelligence Hash Enricher

A Python CLI tool designed for SOC Analysts to query and enrich file hashes using the Hybrid Analysis API v2.

## Features
- Direct SHA256 overview lookups via Hybrid Analysis REST API.
- Fallback hash searching (supports MD5 / SHA1 / SHA256).
- Secure API Key management using `.env` files.

## Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/boogyeman228/ProjHybridAnalyst.git](https://github.com/boogyeman228/ProjHybridAnalyst.git)
   cd ProjHybridAnalyst

## Install dependencies:
pip install -r req.txt

### Configure Environment Variables:
Create a .env file in the root directory based on .env.example:

API_TOKEN=your_actual_api_token_here

# Usage:
Run the script with a file hash as an argument:
python enricher.py 84c60822f5e663da52066d56199ed30f1464731a547b7eb71b12b322a468d795

