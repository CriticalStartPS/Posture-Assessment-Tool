# Azure Security Posture Assessment Tool

This comprehensive security assessment tool evaluates your Microsoft 365 environment's security posture by checking compliance against predefined security requirements. It covers Conditional Access policies, Authorization policies, and Defender for Office 365 Anti-Spam configurations.

## 🔍 Assessment Coverage

### 1. **Conditional Access Policies**
- Multi-factor authentication requirements
- Risk-based policies (user and sign-in risk)
- Device compliance and platform restrictions
- Legacy authentication blocking
- Session controls and app restrictions

### 2. **Authorization Policies** 
- User consent and application creation restrictions
- Guest user permissions and invitation controls
- Administrative access controls
- Security feature configurations

### 3. **Defender for Office 365 Anti-Spam Policies**
- **Inbound Protection (Standard)**: Balanced security settings for most organizations
- **Inbound Protection (Strict)**: Enhanced security for high-risk environments
- **Outbound Protection**: Email reputation and spam prevention controls

## 🏗️ Components

### 1. GraphAuthenticator
Handles authentication with Microsoft Graph using device code flow and secure token caching.

### 2. ConditionalAccessPolicyHandler
Fetches and evaluates Conditional Access policies from Microsoft Graph against security requirements.

### 3. AuthorizationPolicyHandler
Retrieves and checks organization-level authorization policies for security compliance.

### 4. AntiSpamPolicyHandler
Connects to Exchange Online to evaluate both inbound and outbound anti-spam policies with support for:
- Standard protection level (balanced security)
- Strict protection level (enhanced security)
- Outbound spam filtering controls

### 5. ReportGenerator
Generates comprehensive HTML reports with detailed compliance analysis and visual indicators.

## 📋 Requirements

### Prerequisites
- Python 3.7 or higher
- Microsoft 365 tenant with appropriate permissions
- Exchange Online PowerShell module (for anti-spam checks)

### Required Permissions
- **Microsoft Graph**: 
  - `Policy.Read.All` (Conditional Access)
  - `Policy.ReadWrite.AuthorizationPolicy` (Authorization Policies)
- **Exchange Online**: 
  - Exchange Administrator or Global Administrator role

### Python Dependencies
Install required packages:
```bash
pip install -r requirements.txt
```

### Exchange Online Module
For anti-spam policy checking, install the Exchange Online Management module:
```powershell
Install-Module -Name ExchangeOnlineManagement -Force
```

## ⚙️ Configuration Files

The tool uses YAML configuration files to define security requirements:

### Conditional Access
- `config/ConditionalAccess/policy_requirements.yaml`

### Authorization Policies  
- `config/AuthorizationPolicy/policy_requirements.yaml`

### Anti-Spam Policies
- `config/DefenderForOffice365/antispam_inbound_standard_requirements.yaml` - Standard protection
- `config/DefenderForOffice365/antispam_inbound_strict_requirements.yaml` - Strict protection  
- `config/DefenderForOffice365/antispam_outbound_requirements.yaml` - Outbound controls

## 🚀 How It Works

### 1. **Authentication Flow**
- Device code authentication with Microsoft Graph
- Secure token caching to avoid repeated authentication
- Interactive Exchange Online authentication for anti-spam checks

### 2. **Policy Assessment**
- **Conditional Access**: Retrieves all CA policies and matches against requirements
- **Authorization**: Evaluates tenant-level authorization settings
- **Anti-Spam**: Connects to Exchange Online to assess inbound/outbound filtering

### 3. **Compliance Evaluation**
- Checks each policy against defined security baselines
- Supports multiple protection levels (Standard vs Strict)
- Provides detailed per-policy compliance status

### 4. **Report Generation**
- Creates comprehensive HTML reports with visual indicators
- Organizes results by policy type and protection level
- Includes executive summary with overall compliance metrics

## 📊 Protection Levels

### Standard Protection (📋)
- **Target**: Most organizations with balanced security needs
- **Approach**: Moderate filtering, user-friendly actions
- **Example**: Bulk email threshold of 7, move spam to Junk folder

### Strict Protection (🔒)  
- **Target**: High-security environments, sensitive industries
- **Approach**: Aggressive filtering, strict actions
- **Example**: Bulk email threshold of 4, quarantine/delete threats

## 🎯 Running the Tool

### Basic Execution
```bash
python main.py
```

### Authentication Process
1. **Microsoft Graph**: Follow device code prompts for tenant authentication
2. **Exchange Online**: Sign in when prompted for anti-spam policy access

### Report Output
- HTML reports generated in `Reports/` directory
- Timestamped filenames for tracking assessments over time
- Organized sections for each policy type

## 📈 Report Features

### Executive Summary
- Overall compliance percentage
- Policy-specific compliance metrics
- Visual compliance indicators

### Detailed Analysis
- **Standard Inbound Policies**: Balanced security settings
- **Strict Inbound Policies**: Enhanced security configurations  
- **Outbound Policies**: Email reputation controls
- **Policy Breakdowns**: Individual policy compliance status

### Visual Indicators
- ✅ Compliant policies (green)
- ❌ Non-compliant policies (red)
- 📋 Standard protection level
- 🔒 Strict protection level
- 📤 Outbound controls

## 🔧 Troubleshooting

### Common Issues

**Exchange Online Module Missing**
```powershell
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
```

**Permission Errors**
- Ensure you have Exchange Administrator or Global Administrator role
- Verify Microsoft Graph permissions are granted

**Connection Timeouts**
- Check network connectivity
- Ensure PowerShell execution policy allows module loading

### Legacy File Support
The tool maintains backward compatibility with older configuration files:
- `antispam_requirements.yaml` (legacy single file)
- `antispam_inbound_requirements.yaml` (legacy inbound only)

## 📝 Sample Output

```
=== Azure Security Posture Assessment ===
Overall Compliance: 75% (30/40 Policies)

Conditional Access: 94% (17/18 Passed)
Authorization Policies: 43% (3/7 Passed)  
Anti-Spam Standard: 83% (10/12 Passed)
Anti-Spam Strict: 67% (8/12 Passed)
Outbound Policies: 88% (7/8 Passed)
```

## 🤝 Contributing

This tool is designed to be extensible. To add new policy types:
1. Create appropriate handler class
2. Add YAML configuration file
3. Update main.py integration
4. Enhance report template

## 📄 License

MIT License - See LICENSE file for details.
