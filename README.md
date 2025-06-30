# Azure Security Posture Assessment Tool

This comprehensive security assessment tool evaluates your Microsoft 365 environment's security posture by checking compliance against predefined security requirements. It covers Conditional Access policies, Authorization policies, and comprehensive Defender for Office 365 protection including Anti-Spam, Anti-Phishing, and Anti-Malware configurations.

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

### 4. **Defender for Office 365 Anti-Phishing Policies**
- **Standard Protection**: Baseline anti-phishing settings for general security
- **Strict Protection**: Advanced anti-phishing controls for high-security environments
- Spoofing protection, impersonation detection, and mailbox intelligence

### 5. **Defender for Office 365 Anti-Malware Policies**
- File filtering and dangerous file type blocking
- Zero-hour Auto Purge (ZAP) for retroactive threat removal
- Quarantine management and notification controls
- Comprehensive malware protection settings

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

### 5. AntiPhishingPolicyHandler
Evaluates anti-phishing policies in Exchange Online with support for:
- Standard protection configurations
- Strict protection configurations
- Spoofing intelligence and impersonation detection
- Mailbox intelligence and safety tips

### 6. AntiMalwarePolicyHandler
Assesses anti-malware policies in Exchange Online including:
- File filtering and dangerous file type blocking
- Zero-hour Auto Purge (ZAP) settings
- Quarantine tag configurations
- Notification and admin alert settings

### 7. ExchangeOnlineSessionManager
Manages single-session authentication to Exchange Online for efficient policy retrieval across all Defender for Office 365 handlers:
- Shared session management for anti-spam, anti-phishing, and anti-malware checks
- Reduces authentication overhead and improves performance
- Handles PowerShell module detection and execution

### 8. ReportGenerator
Generates comprehensive HTML reports with detailed compliance analysis and visual indicators for all policy types.

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
  - Required for anti-spam, anti-phishing, and anti-malware policy checks

### Python Dependencies
Install required packages:
```bash
pip install -r requirements.txt
```

### Exchange Online Module
For Defender for Office 365 policy checking (anti-spam, anti-phishing, anti-malware), install the Exchange Online Management module:
```powershell
Install-Module -Name ExchangeOnlineManagement -Force
```

## ⚙️ Configuration Files

The tool uses YAML configuration files to define security requirements:

### Conditional Access
- `config/ConditionalAccess/policy_requirements.yaml`

### Authorization Policies  
- `config/AuthorizationPolicy/policy_requirements.yaml`

### Defender for Office 365 Policies

#### Anti-Spam Policies
- `config/DefenderForOffice365/antispam_inbound_standard_requirements.yaml` - Standard protection
- `config/DefenderForOffice365/antispam_inbound_strict_requirements.yaml` - Strict protection  
- `config/DefenderForOffice365/antispam_outbound_requirements.yaml` - Outbound controls

#### Anti-Phishing Policies
- `config/DefenderForOffice365/antiphishing_standard_requirements.yaml` - Standard protection
- `config/DefenderForOffice365/antiphishing_strict_requirements.yaml` - Strict protection

#### Anti-Malware Policies
- `config/DefenderForOffice365/antimalware_requirements.yaml` - Malware protection settings

## 🚀 How It Works

### 1. **Authentication Flow**
- Device code authentication with Microsoft Graph
- Secure token caching to avoid repeated authentication
- Interactive Exchange Online authentication for anti-spam checks

### 2. **Policy Assessment**
- **Conditional Access**: Retrieves all CA policies and matches against requirements
- **Authorization**: Evaluates tenant-level authorization settings
- **Defender for Office 365**: Uses shared session management to efficiently assess:
  - **Anti-Spam**: Connects to Exchange Online to assess inbound/outbound filtering
  - **Anti-Phishing**: Evaluates spoofing protection and impersonation detection
  - **Anti-Malware**: Checks file filtering, ZAP settings, and quarantine policies

### 3. **Compliance Evaluation**
- Checks each policy against defined security baselines
- Supports multiple protection levels (Standard vs Strict)
- Provides detailed per-policy compliance status
- **Special Logic**:
  - **Anti-Malware FileTypes**: Case-insensitive array comparison ensuring all dangerous file types are blocked
  - **Anti-Phishing**: Advanced spoofing and impersonation detection checks
  - **Policy-Level Compliance**: Requirements met when at least one policy satisfies all criteria

### 4. **Report Generation**
- Creates comprehensive HTML reports with visual indicators
- Organizes results by policy type and protection level
- Includes executive summary with overall compliance metrics
- **Enhanced Sections**:
  - Anti-Spam (Inbound Standard, Inbound Strict, Outbound)
  - Anti-Phishing (Standard, Strict)
  - Anti-Malware (File filtering, ZAP, Quarantine)

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
2. **Exchange Online**: Single sign-in session for all Defender for Office 365 policy checks (anti-spam, anti-phishing, anti-malware)

### Report Output
- HTML reports generated in `Reports/` directory
- Timestamped filenames for tracking assessments over time
- Organized sections for each policy type

## 📈 Report Features

### Executive Summary
- Overall compliance percentage
- Policy-specific compliance metrics for all assessment areas
- Visual compliance indicators

### Detailed Analysis
- **Conditional Access**: Identity and access controls
- **Authorization Policies**: Tenant-level security settings
- **Standard Inbound Anti-Spam**: Balanced security settings
- **Strict Inbound Anti-Spam**: Enhanced security configurations  
- **Outbound Anti-Spam**: Email reputation controls
- **Standard Anti-Phishing**: Baseline spoofing and impersonation protection
- **Strict Anti-Phishing**: Advanced threat detection and response
- **Anti-Malware**: File filtering, ZAP, and quarantine management
- **Policy Breakdowns**: Individual policy compliance status for each category

### Visual Indicators
- ✅ Compliant policies (green)
- ❌ Non-compliant policies (red)
- 📋 Standard protection level
- 🔒 Strict protection level
- 📤 Outbound controls
- 🎣 Anti-phishing protection
- 🦠 Anti-malware protection

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

## 🔧 New Features & Implementation Details

### Anti-Malware Policy Handler
**Implementation**: Complete anti-malware policy assessment with configuration-focused requirements:

**Key Features**:
- **File Type Filtering**: Comprehensive blocking of dangerous file extensions (77+ file types)
- **ZAP (Zero-hour Auto Purge)**: Retroactive threat removal from mailboxes
- **Quarantine Management**: Admin-only access policies for quarantined items
- **Notification Controls**: Disabled custom notifications for security consistency

**Configuration Requirements** (`antimalware_requirements.yaml`):
- File Filter Enabled: `EnableFileFilter: true`
- File Type Action: `FileTypeAction: "Quarantine"`
- Comprehensive File Types: Blocks 77+ dangerous extensions including executables, scripts, and malicious document types
- ZAP Enabled: `ZapEnabled: true`
- Quarantine Tag: `QuarantineTag: "AdminOnlyAccessPolicy"`
- Notification Settings: All custom notifications disabled for security

### Anti-Phishing Policy Handler
**Implementation**: Enhanced anti-phishing protection with standard and strict protection levels:

**Standard Protection**:
- Basic spoofing protection and mailbox intelligence
- Balanced user experience with security controls
- User safety tips and warnings

**Strict Protection**:
- Advanced spoofing protection with strict thresholds
- Enhanced impersonation detection for users and domains
- Aggressive action policies (quarantine vs. junk folder)

### Single Session Management
**ExchangeOnlineSessionManager Enhancement**:
- **Shared Authentication**: Single sign-in session for all Defender for Office 365 checks
- **Policy Type Support**: Anti-spam, anti-phishing, and anti-malware in one session
- **PowerShell Integration**: Efficient cmdlet execution with proper error handling
- **Performance Optimization**: Reduces authentication overhead and improves execution time

## 📝 Sample Output

```
=== Azure Security Posture Assessment ===
Overall Compliance: 78% (47/60 Policies)

Conditional Access: 94% (17/18 Passed)
Authorization Policies: 43% (3/7 Passed)  
Anti-Spam Standard: 83% (10/12 Passed)
Anti-Spam Strict: 67% (8/12 Passed)
Outbound Policies: 88% (7/8 Passed)
Anti-Phishing Standard: 92% (11/12 Passed)
Anti-Phishing Strict: 75% (9/12 Passed)
Anti-Malware: 100% (8/8 Passed)
```

## 🔧 Advanced Configuration

### File Type Blocking (Anti-Malware)
The anti-malware handler includes comprehensive file type blocking covering:
- **Executables**: .exe, .com, .scr, .pif, .msi, .app, .deb
- **Scripts**: .bat, .cmd, .ps1, .vbs, .js, .vb
- **Archives**: .zip, .rar, .7z, .cab, .iso, .img
- **Dangerous Documents**: .docm, .xlm, .ppa, .ppam
- **System Files**: .dll, .sys, .lib, .kext
- **And 60+ more dangerous file types**

### Protection Level Mapping
- **Standard**: Baseline security suitable for most organizations
- **Strict**: Enhanced security for high-risk environments, sensitive data, or regulatory compliance
- **Custom**: Ability to define organization-specific requirements in YAML files

## 🤝 Contributing

This tool is designed to be extensible. To add new policy types:
1. Create appropriate handler class (following existing patterns)
2. Add YAML configuration file with requirements
3. Update main.py integration and ExchangeOnlineSessionManager if needed
4. Enhance report template for new policy display
5. Update README.md documentation

### Handler Architecture
All Defender for Office 365 handlers follow a consistent pattern:
- **Constructor**: Accept requirements file and shared session manager
- **check_policies()**: Main method returning standardized result format
- **_check_policy_requirements()**: Internal compliance evaluation logic
- **Integration**: Seamless integration with ExchangeOnlineSessionManager

## 📄 License

MIT License - See LICENSE file for details.
