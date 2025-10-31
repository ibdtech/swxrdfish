# swxrdfish
session hijacking framework

git clone https://github.com/ibdtech/swxrdfish.git
cd swxrdfish
pip install -r requirements.txt
python swxrdfish.py
```

## Quick Start

1. Run the tool and select beginner mode if this is your first time
2. Choose option 1 to start the public callback server
3. Select your preferred tunnel type (ngrok recommended)
4. Copy your public callback URL
5. Generate payloads using option 2
6. Deploy your payloads on target websites
7. View captured victims in option 3 or the web dashboard (option 6)

## Usage Guide

### Starting the Callback Server

The callback server is where all victim data gets sent. When you start it, Swxrdfish will automatically create a public URL using either ngrok or cloudflare tunnels.
```
[1] Start Public Callback Server
```

Choose your tunnel type:
- Auto: Tries ngrok first, falls back to cloudflare, then local
- Ngrok: Best option, requires ngrok installed
- Cloudflare: Free alternative, requires cloudflared
- Local: No public URL, only works on your network

You can optionally configure a Discord webhook URL to get real-time notifications when victims are captured.

### Generating Payloads

Swxrdfish includes several payload types:

- Basic Cookie Stealer: Simple fetch request to exfiltrate cookies
- Advanced Exfiltration: Captures cookies, localStorage, and sessionStorage
- BeEF Hook Persistent: Full C2 capability with keylogging and form capture
- Screenshot Capture: Uses html2canvas to screenshot the victim's page
- DOM Exfiltration: Steals the entire page HTML
- Multi-stage Loader: Loads additional JavaScript from your server
- WAF Bypass: Various encoding and obfuscation techniques

Each payload is automatically configured with your callback URL and optional campaign ID for tracking.

### Viewing Captured Data

All victim data is stored in a local SQLite database. You can view it through:

- The terminal interface (option 3)
- The web dashboard (option 6)
- Direct database access at swxrdfish_victims.db

The database stores:
- Victim metadata (IP, timestamp, user agent)
- All cookies
- JWT and authentication tokens
- localStorage contents
- sessionStorage contents
- Campaign tracking information

### JWT Exploitation

The JWT module performs comprehensive analysis:

- Detects "none" algorithm vulnerabilities
- Brute forces weak signing secrets
- Tests for algorithm confusion attacks
- Identifies JKU/JWK header injection points
- Finds KID SQL injection vectors
- Automatically generates privilege escalation tokens

Just paste any JWT token and the tool will analyze it and generate exploit payloads.

### Session Replay

This feature requires Selenium and attempts to hijack a victim's session automatically:

1. Select a victim from your database
2. Enter the target website URL
3. Swxrdfish loads the site with the victim's cookies
4. Takes a screenshot
5. Analyzes the page to determine if authentication succeeded
6. Detects admin access indicators

### Web Dashboard

Access the dashboard at http://localhost:5000 after starting it from option 6. Features:

- Auto-refreshing victim list
- Statistics overview
- Token collection counts
- Campaign tracking
- Browser fingerprinting data

The dashboard updates every 10 seconds automatically.

## Configuration

### Webhook Notifications

Configure webhooks in option 7 to receive instant notifications when victims are captured. Supports:

- Discord webhooks
- Slack webhooks

The notification includes victim ID, IP address, campaign ID, and a preview of captured cookies.

### Campaign Tracking

Use campaign IDs to track different payloads or target applications. Set the campaign ID when generating payloads, and it will be associated with all data from that payload.

### Database Location

The victim database is stored at swxrdfish_victims.db in the current directory. All output files go to the swxrdfish_output directory.

## Beginner Mode

Beginner mode adds educational content and step-by-step guidance. It includes:

- Detailed explanations of XSS concepts
- Callback server mechanics
- JWT token structure and attacks
- Interactive pauses between steps
- Tips and best practices

Enable it when prompted at startup or toggle it in option 9.

## Security Considerations

This tool is designed for authorized security testing only. Use it responsibly:

- Only test applications you have explicit permission to test
- Never deploy payloads on production systems without authorization
- Be aware that capturing user data may have legal implications
- Some payload types (like keyloggers) are particularly invasive
- Always follow your bug bounty program's rules and scope

## Common Use Cases

### Bug Bounty Testing

1. Find an XSS vulnerability on a target in scope
2. Start Swxrdfish callback server with ngrok tunnel
3. Generate a basic cookie stealer payload
4. Test the payload to confirm it works
5. If successful, analyze captured tokens for privilege escalation
6. Report the vulnerability with evidence from Swxrdfish

### Session Token Analysis

1. Capture a JWT token through XSS
2. Use the JWT exploitation module to analyze it
3. Test for weak secrets or algorithm confusion
4. Generate forged tokens with elevated privileges
5. Use session replay to test the forged tokens

### Persistent Access Testing

1. Deploy a BeEF hook payload
2. Wait for admin users to trigger the XSS
3. Use the C2 functionality to send commands
4. Capture keystrokes and form submissions
5. Screenshot sensitive admin panels

## Troubleshooting

### Tunnel Connection Issues

If ngrok or cloudflare tunnels fail to start:
- Verify the binary is in your PATH
- Check if ports 4040 (ngrok) or 8000 (cloudflare) are available
- Try the local only option and use port forwarding manually

### No Victims Captured

Common reasons:
- Callback server not running
- XSS payload blocked by CSP or XSS filters
- Victim browser blocking third-party requests
- Wrong callback URL in the payload

### Session Replay Fails

Requirements:
- Selenium must be installed
- Chrome/Chromium browser required
- Victim must have valid session cookies
- Target site must not have additional anti-automation measures

## File Structure
```
swxrdfish/
├── swxrdfish.py              # Main application
├── swxrdfish_victims.db      # SQLite database
└── swxrdfish_output/         # Generated payloads and screenshots


______________________________________________________________________________


Here's the suggested workflow order for beginners:

Start Public Callback Server [Beginner]:

This is the first step as it sets up the foundation for capturing data.
It's essential to have a working server before generating payloads or viewing captured data.
Generate Advanced Payloads [Beginner]:

Once the server is running, you can generate payloads to deploy on target websites.
This step requires the callback URL provided by the server.
View Captured Victims [Beginner]:

After deploying payloads, you can view captured victims in the database.
This step helps you understand the data being collected and how to analyze it.
JWT Exploitation [Beginner]:

If you capture JWT tokens, you can analyze and exploit them using this feature.
This step builds on the data captured in the previous steps.
Session Replay Auto Hijack:

Once you have captured sessions, you can attempt to replay them to gain access.
This step requires a deeper understanding of the captured data and the target environment.
Web Dashboard:

The web dashboard provides a visual interface for monitoring captured data.
This step complements the command-line interface and makes it easier to analyze data.
Configure Webhooks:

Setting up webhooks allows you to receive notifications when new data is captured.
This step enhances the overall monitoring experience.
Database Statistics:

Finally, reviewing database statistics gives you an overview of the captured data.
This step helps you understand the effectiveness of your campaigns and identify areas for improvement.


Understanding how such a tool works is crucial because it enables you to:

Secure Systems: Learn how attackers operate to better defend against similar attacks.
Understand Threats: Gain insight into the methods used by cybercriminals to compromise systems.
Improve Security Posture: Apply knowledge to strengthen defenses and reduce vulnerabilities.
Develop Countermeasures: Create effective strategies to mitigate potential security risks.
Stay Updated: Keep pace with evolving cyber threats and security trends.
Build Trust: Understand the underlying mechanisms to trust security tools and their reports.
Innovate: Use the principles learned to develop new security solutions and tools.
Ethical Hacking: Apply knowledge ethically to test and improve system security.
This understanding empowers individuals and organizations to proactively protect themselves in the ever-evolving landscape of cybersecurity.


