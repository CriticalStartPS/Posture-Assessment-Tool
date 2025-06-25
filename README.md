# Security Health Check

This project is designed to check the compliance of Conditional Access policies against a set of predefined requirements. It authenticates with Microsoft Graph, retrieves Conditional Access policies, checks them against the requirements, and generates a report.

## Components

### 1. GraphAuthenticator
Handles authentication with Microsoft Graph using device code flow and token caching.

### 2. ConditionalAccessPolicyHandler
Fetches and checks Conditional Access policies from Microsoft Graph.

### 3. ReportGenerator
Generates a PDF report summarizing the compliance of the policies.

## How It Works

1. **Authentication**: The `GraphAuthenticator` class authenticates with Microsoft Graph using device code flow. It caches the token to avoid repeated authentication.

2. **Retrieve and Check Policies**: The `ConditionalAccessPolicyHandler` class retrieves all Conditional Access policies from Microsoft Graph and checks them against the predefined requirements specified in a YAML file.

3. **Generate Report**: The `ReportGenerator` class generates a PDF report summarizing the compliance of the policies.

## Running the Tool

To run the tool, execute the `main.py` script. It will authenticate with Microsoft Graph, retrieve the policies, check them against the requirements, and generate a PDF report.
