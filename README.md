# AWS IAM Access Key Audit Script

## Overview
This Python script audits AWS IAM users' access keys across an AWS account. It identifies active access keys that have not been used for more than 90 days. This helps in enhancing security by monitoring and managing credentials.
It scans all keys against all users. Most scripts would check just the first access key. This one covers the case when one user has multiple access keys.

## Features
- **Multithreading**: Utilizes Python threading for concurrent processing of multiple IAM users, improving performance.
- **Access Key Status Check**: Audits only active access keys.
- **Usage Tracking**: Reports the number of days each active key has been unused.

## Prerequisites
- Python 3.x
- Boto3 library
- AWS credentials (Access Key ID, Secret Access Key, and optionally Session Token) set as environment variables.

## Installation

1. **Install Python 3.x**:
   Ensure Python 3.x is installed on your system. Download from [Python's official site](https://www.python.org/downloads/).

2. **Install Boto3**:
   Use pip to install the Boto3 library.
   ```bash
   pip install boto3

3. **Set AWS Credentials:**
   Set your AWS credentials as environment variables.
   ```bash
   export AWS_ACCESS_KEY_ID="your_access_key_id"
   export AWS_SECRET_ACCESS_KEY="your_secret_access_key"
   export AWS_SESSION_TOKEN="your_session_token"  # Optional

## Usage
Simply run the script in your Python environment. Ensure that your AWS credentials are set in the environment variables before execution.

