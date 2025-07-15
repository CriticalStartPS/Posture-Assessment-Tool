# Posture Assessment Tool

A comprehensive security assessment tool that evaluates your Microsoft 365 environment's security posture by checking compliance against predefined security requirements. This tool covers Conditional Access policies, Authorization policies, and comprehensive Defender for Office 365 protection including Anti-Spam, Anti-Phishing, and Anti-Malware configurations.

## 📝 Setup Instructions

### Step 1: Install Prerequisites

#### 1.1 Install Git
1. Download and install [Git for Windows](https://git-scm.com/download/win)
2. During installation, select "Use Git from the Windows Command Prompt"
3. Complete the installation with default settings

#### 1.2 Install Visual Studio Code
1. Download and install [Visual Studio Code](https://code.visualstudio.com/)
2. Launch VS Code after installation

#### 1.3 Install Python
1. Download and install [Python 3.7 or higher](https://www.python.org/downloads/)
2. **Important**: Check "Add Python to PATH" during installation
3. Verify installation by opening Command Prompt and typing: `python --version`

#### 1.4 Install PowerShell 7
1. Download and install [PowerShell 7](https://github.com/PowerShell/PowerShell/releases/latest)
2. Follow the installation wizard with default settings
3. Verify installation by opening PowerShell 7 and typing: `$PSVersionTable.PSVersion`

#### 1.5 Install VS Code Extensions
1. Open VS Code
2. Go to Extensions (Ctrl + Shift + X)
3. Search for and install "PowerShell" extension by Microsoft
4. Search for and install "Python" extension by Microsoft (if not already installed)

### Step 2: Clone the Repository

1. Open VS Code
2. Press `Ctrl + Shift + P` to open Command Palette
3. Type "Git: Clone" and select it
4. Enter the repository URL: `https://github.com/JohnnyMonz93/Posture-Assessment-Tool.git`
5. Choose a local folder to clone the repository
6. Click "Open" when prompted to open the cloned repository

### Step 3: Set Up Python Environment

1. Open VS Code Command Palette: Press `Ctrl + Shift + P`
2. Type "Python: Create Environment" and select it
3. Choose "Venv" when prompted for environment type
4. Select your Python interpreter (the one you installed in Step 1.3)
5. When prompted to select dependencies, check the box for `requirements.txt`
6. Click "OK" to create the environment and install dependencies automatically
7. VS Code will create the virtual environment and install all required packages for you

### Step 4: Install Exchange Online PowerShell Module

1. Open PowerShell as Administrator
2. Install the Exchange Online Management module:
   ```powershell
   Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
   ```
3. If prompted about installing from PSGallery, type `Y` and press Enter

### Step 5: Configure Microsoft 365 Permissions

#### 5.1 Microsoft Graph Permissions
Ensure your account has the following Microsoft Graph permissions:
- `Policy.Read.All` (for Conditional Access policies)
- `Policy.Read.AuthorizationPolicy` (for Authorization policies)
- `DeviceManagementConfiguration.Read.All` (for Defender for Endpoint)

#### 5.2 Entra Role Permissions
Your account needs both of the following roles:
- **Global Reader**
- **Security Reader**

### Step 6: Run the Tool

1. In VS Code Terminal, run:
   ```powershell
   python main.py
   ```
2. Follow the authentication prompts:
   - **Microsoft Graph**: Use device code authentication
   - **Exchange Online**: Sign in when prompted
3. Wait for the assessment to complete
4. Find your HTML report in the `Reports/` folder

### Step 7: View Results

1. Navigate to the `Reports/` folder in your project
2. Open the latest HTML report file (timestamped filename)
3. Review your security posture assessment results

## 🔧 Troubleshooting Setup Issues

### Python Not Found
- Ensure Python is added to your system PATH
- Restart VS Code after Python installation
- Try `py` instead of `python` command

### Virtual Environment Issues
- Ensure you're in the correct project directory
- Check PowerShell execution policy: `Get-ExecutionPolicy`
- Use full path to activate script if needed

### Exchange Online Module Issues
- Run PowerShell as Administrator
- Update PowerShellGet: `Install-Module PowerShellGet -Force`
- Try: `Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser`

### Permission Errors
- Verify your Microsoft 365 account has required roles
- Contact your tenant administrator for proper permissions
- Ensure you're signing in with the correct account

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

### 6. **Defender for Endpoint Antivirus Configurations**
- Microsoft Defender Antivirus security configurations from Intune
- Real-time protection and cloud-delivered protection settings
- Scan settings and exclusion configurations
- Advanced threat protection features

### 7. **Defender for Endpoint Attack Surface Reduction (ASR)**
- Attack Surface Reduction rules and configurations from Intune
- Malicious behavior blocking and prevention
- Office application protection rules
- Script and macro execution controls
- Email and web threat protection rules

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

### 7. AntivirusConfigHandler
Evaluates Microsoft Defender Antivirus configurations from Intune including:
- Real-time protection and cloud-delivered protection settings
- Scan configurations and exclusion policies
- Advanced threat protection features
- Policy compliance across managed devices

### 8. AttackSurfaceReductionConfigHandler
Assesses Attack Surface Reduction (ASR) rules and configurations from Intune including:
- Malicious behavior blocking and prevention rules
- Office application protection configurations
- Script and macro execution controls
- Email and web threat protection settings
- ASR rule enablement and action modes (Block, Audit, Warn)

### 9. ExchangeOnlineSessionManager
Manages single-session authentication to Exchange Online for efficient policy retrieval across all Defender for Office 365 handlers:
- Shared session management for anti-spam, anti-phishing, and anti-malware checks
- Reduces authentication overhead and improves performance
- Handles PowerShell module detection and execution

### 10. ReportGenerator
Generates comprehensive HTML reports with detailed compliance analysis and visual indicators for all policy types.

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

### Defender for Endpoint Policies

#### Antivirus Configurations
- `config/DefenderForEndpoint/antivirus_requirements.yaml` - Defender antivirus settings

#### Attack Surface Reduction (ASR)
- `config/DefenderForEndpoint/asr_requirements.yaml` - ASR rules and protection settings

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
- **Defender for Endpoint**: Uses Microsoft Graph API to assess Intune configurations:
  - **Antivirus**: Evaluates Defender antivirus protection settings and policies
  - **Attack Surface Reduction**: Checks ASR rules and malicious behavior blocking

### 3. **Compliance Evaluation**
- Checks each policy against defined security baselines
- Supports multiple protection levels (Standard vs Strict)
- Provides detailed per-policy compliance status
- **Special Logic**:
  - **Anti-Malware FileTypes**: Case-insensitive array comparison ensuring all dangerous file types are blocked
  - **Anti-Phishing**: Advanced spoofing and impersonation detection checks
  - **Defender for Endpoint**: Direct compliance evaluation using `is_compliant` field from Intune configurations
  - **Policy-Level Compliance**: Requirements met when at least one policy satisfies all criteria

### 4. **Report Generation**
- Creates comprehensive HTML reports with visual indicators
- Organizes results by policy type and protection level
- Includes executive summary with overall compliance metrics
- **Enhanced Sections**:
  - Anti-Spam (Inbound Standard, Inbound Strict, Outbound)
  - Anti-Phishing (Standard, Strict)
  - Anti-Malware (File filtering, ZAP, Quarantine)
  - Defender for Endpoint Antivirus (Protection settings, Scan configurations)
  - Attack Surface Reduction (ASR rules, Behavior blocking)

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
- **Defender for Endpoint Antivirus**: Real-time protection and scan configurations
- **Attack Surface Reduction**: ASR rules and malicious behavior blocking
- **Policy Breakdowns**: Individual policy compliance status for each category

### Visual Indicators
- ✅ Compliant policies (green)
- ❌ Non-compliant policies (red)
- 📋 Standard protection level
- 🔒 Strict protection level
- 📤 Outbound controls
- 🎣 Anti-phishing protection
- 🦠 Anti-malware protection
- 🛡️ Defender for Endpoint protection (Antivirus & ASR)

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
Overall Compliance: 82% (65/79 Policies)

Conditional Access: 94% (17/18 Passed)
Authorization Policies: 43% (3/7 Passed)  
Anti-Spam Standard: 83% (10/12 Passed)
Anti-Spam Strict: 67% (8/12 Passed)
Outbound Policies: 88% (7/8 Passed)
Anti-Phishing Standard: 92% (11/12 Passed)
Anti-Phishing Strict: 75% (9/12 Passed)
Anti-Malware: 100% (8/8 Passed)
Defender for Endpoint Antivirus: 89% (8/9 Passed)
Attack Surface Reduction: 91% (10/11 Passed)
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

### Attack Surface Reduction (ASR) Rules
The ASR handler supports comprehensive evaluation of Microsoft Defender ASR rules including:

#### Core ASR Rules
- **Block executable files**: Prevent potentially malicious executable files from running
- **Block Office applications**: Control Office app behavior to prevent malicious activity
- **Block credential stealing**: Prevent credential harvesting from Windows security subsystem
- **Block process creations**: Control process creation from Office communication applications
- **Block untrusted processes**: Prevent untrusted and unsigned processes from running from USB
- **Block JavaScript/VBScript**: Control script execution in email and web content
- **Block Adobe Reader**: Prevent Adobe Reader from creating child processes
- **Block Win32 API calls**: Control API calls from Office macros
- **Advanced boot protection**: Block persistence through WMI event subscription

#### ASR Rule Actions
- **Block**: Prevent the activity (recommended for production)
- **Audit**: Log the activity without blocking (recommended for testing)
- **Warn**: Prompt user with warning before allowing activity
- **Not Configured**: Rule is disabled

#### Configuration Requirements
The ASR requirements file (`asr_requirements.yaml`) defines expected rule states and actions for comprehensive endpoint protection.

## 🤝 Contributing

This tool is designed to be extensible. To add new policy types:
1. Create appropriate handler class (following existing patterns)
2. Add YAML configuration file with requirements
3. Update main.py integration and ExchangeOnlineSessionManager if needed
4. Enhance report template for new policy display
5. Update README.md documentation

### Handler Architecture
All handlers follow a consistent pattern:
- **Defender for Office 365 handlers**: Accept requirements file and shared ExchangeOnlineSessionManager
- **Defender for Endpoint handlers**: Accept requirements file and Microsoft Graph token for Intune API access
- **check_policies()**: Main method returning standardized result format with `is_compliant` field
- **_check_policy_requirements()**: Internal compliance evaluation logic
- **Integration**: Seamless integration with respective session managers and APIs

## 📄 License

MIT License - See LICENSE file for details.
