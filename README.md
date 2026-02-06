# juniper_grokoid

Convert Juniper Junos OS syslog messages into Graylog Grok extractors — automatically.

If you run Juniper SRX, EX, MX, or QFX devices and use **Graylog** for log management, this tool saves you from manually writing hundreds of Grok patterns. It reads Juniper's official syslog reference spreadsheet and generates a ready-to-import JSON file for Graylog.

## What It Does

```
Juniper Syslog Excel Spreadsheet  ──►  juniper_grokoid  ──►  Graylog Extractor JSON
```

Juniper publishes an Excel file documenting every syslog message in Junos OS, including the message templates with variable fields like `<variable>source-address</variable>`. This tool:

1. Reads that spreadsheet
2. Converts each message template into a [Grok pattern](https://go2docs.graylog.org/current/getting_in_log_data/extractors.html)
3. Outputs a JSON file you can import directly into Graylog as extractors

For example, this Junos syslog template:

```
session denied <variable>source-address</variable>/<variable>source-port</variable>->
<variable>destination-address</variable>/<variable>destination-port</variable>
```

Becomes this Grok pattern:

```
session denied %{IP:source_address}/%{NUMBER:source_port}->%{IP:destination_address}/%{NUMBER:destination_port}
```

## Quick Start

### 1. Download the Junos Syslog Spreadsheet

Go to Juniper's **System Log Explorer** page for your Junos version:

> https://www.juniper.net/documentation/us/en/software/junos/syslog-messages/topics/topic-map/syslog-explorer-top.html

Click **"Download as Excel"** and save the `.xlsx` file into this folder.

### 2. Install Python Dependencies

You need Python 3.8+ (most Macs and Linux machines already have it).

```bash
pip install -r requirements.txt
```

This installs `openpyxl`, the library used to read Excel files.

### 3. Generate the Extractors

```bash
python3 juniper_grokoid.py -i <your-spreadsheet>.xlsx -o extractors.json
```

That's it. You now have `extractors.json` ready for Graylog.

### 4. Import into Graylog

1. In Graylog, go to **System** > **Inputs**
2. Click **Manage extractors** on your syslog input
3. Click **Actions** > **Import extractors**
4. Paste or upload the contents of `extractors.json`

## Usage Examples

```bash
# Generate extractors for ALL categories
python3 juniper_grokoid.py -i syslog_messages.xlsx -o extractors.json

# Only generate firewall/security and traffic flow extractors
python3 juniper_grokoid.py -i syslog_messages.xlsx -c security,flow -o extractors.json

# Preview what will be generated (no file written)
python3 juniper_grokoid.py -i syslog_messages.xlsx --dry-run

# See how many extractors per category
python3 juniper_grokoid.py -i syslog_messages.xlsx --stats

# List all available categories
python3 juniper_grokoid.py --list-categories
```

## Categories

Messages are grouped into categories based on their syslog name prefix. Use `--categories` / `-c` to filter which ones you want.

| Category     | What It Covers                        | Syslog Prefixes |
|--------------|---------------------------------------|-----------------|
| **security** | Firewall, IPS, IPsec, screens         | RT_SCREEN_, RT_IPSEC_, IDP_, KMD_, IKE_, IPSEC_, FWAUTH_, SSL_PROXY_, SECINTEL_, PFE_FW_, PFE_SCREEN_, DDOS_ |
| **utm**      | Web filtering, antivirus, antispam    | WEBFILTER_, AAMW_, AV_, ANTI_VIRUS_, ANTISPAM_, URLFD_, UTMD_, ICAP_, APPTRACK_ |
| **flow**     | Session/traffic flows, NAT, ALGs      | RT_FLOW_, RT_ALG_, RT_GTP_, RT_SCTP_, RT_NAT_, RT_SRC_, RT_DST_, RT_STATIC_, FLOW_, PFE_FLOWD_ |
| **chassis**  | Hardware, fans, power, temperature    | CHASSISD_ |
| **routing**  | BGP, OSPF, ISIS, MPLS, EVPN, LDP     | BGP_, RPD_OSPF_, RPD_ISIS_, RPD_BGP_, RPD_LDP_, RPD_MPLS_, RPD_RSVP_, RPD_PIM_, RPD_IGMP_, RPD_MLD_, RPD_KRT_, RPD_RT_, RPD_SPRING_, EVPN_, MPLS_ |

## Example Output

Here are three real extractors from the generated JSON to give you a feel for what you get:

### Flow: Session Create (RT_FLOW_SESSION_CREATE)

Every time a new session is created on your SRX, this extractor pulls out source/destination IPs, ports, NAT translations, protocol, policy name, zones, and application info:

```json
{
  "title": "RT_FLOW_SESSION_CREATE",
  "extractor_type": "grok",
  "converters": [],
  "order": 1275,
  "cursor_strategy": "copy",
  "source_field": "message",
  "target_field": "",
  "extractor_config": {
    "grok_pattern": "session\\ created\\ %{IP:source_address}/%{NUMBER:source_port}\\->%{IP:destination_address}/%{NUMBER:destination_port}\\ 0x%{DATA:connection_tag}\\ %{DATA:service_name}\\ %{IP:nat_source_address}/%{NUMBER:nat_source_port}\\->%{IP:nat_destination_address}/%{NUMBER:nat_destination_port}\\ ..."
  },
  "condition_type": "string",
  "condition_value": "RT_FLOW_SESSION_CREATE"
}
```

Fields extracted: `source_address`, `source_port`, `destination_address`, `destination_port`, `nat_source_address`, `nat_source_port`, `nat_destination_address`, `nat_destination_port`, `src_nat_rule_name`, `dst_nat_rule_name`, `protocol_id`, `policy_name`, `source_zone_name`, `destination_zone_name`, `session_id`, `username`, `application`, and more.

### UTM: Web Filter URL Blocked (WEBFILTER_URL_BLOCKED)

When the SRX blocks a URL via web filtering, this extractor captures the source/destination zones, IPs, ports, the blocked URL, category, reason, and user info:

```json
{
  "title": "WEBFILTER_URL_BLOCKED",
  "extractor_type": "grok",
  "converters": [],
  "order": 1519,
  "cursor_strategy": "copy",
  "source_field": "message",
  "target_field": "",
  "extractor_config": {
    "grok_pattern": "WebFilter:\\ ACTION=\"URL\\ Blocked\"\\ source\\-zone=\"%{DATA:source_zone}\"\\ destination\\-zone=\"%{DATA:destination_zone}\"%{IP:source_address}\\(%{NUMBER:source_port}\\)\\->%{IP:destination_address}\\(%{NUMBER:destination_port}\\)\\ SESSION_ID=%{NUMBER:session_id}\\ APPLICATION=\"%{DATA:application}\"\\ ..."
  },
  "condition_type": "string",
  "condition_value": "WEBFILTER_URL_BLOCKED"
}
```

Fields extracted: `source_zone`, `destination_zone`, `source_address`, `source_port`, `destination_address`, `destination_port`, `session_id`, `application`, `nested_application`, `category`, `reason`, `profile`, `url`, `username`, `roles`.

### Chassis: FRU Over Temperature (CHASSISD_FRU_OVER_TEMP_CONDITION)

If a line card or power supply overheats, this extractor captures which FRU, the sensor, current temperature, threshold, and how long before shutdown:

```json
{
  "title": "CHASSISD_FRU_OVER_TEMP_CONDITION",
  "extractor_type": "grok",
  "converters": [],
  "order": 366,
  "cursor_strategy": "copy",
  "source_field": "message",
  "target_field": "",
  "extractor_config": {
    "grok_pattern": "%{DATA:fru_name}\\ %{DATA:fru_slot}\\ %{DATA:sensor}\\ temperature\\ %{DATA:temperature}\\ over\\ %{DATA:threshold}\\ degrees\\ C\\ \\(%{DATA:message}\\);\\ FRU\\ will\\ shut\\ down\\ in\\ %{DATA:duration}\\ seconds\\ if\\ condition\\ persists"
  },
  "condition_type": "string",
  "condition_value": "CHASSISD_FRU_OVER_TEMP_CONDITION"
}
```

Fields extracted: `fru_name`, `fru_slot`, `sensor`, `temperature`, `threshold`, `message`, `duration`.

## All CLI Options

| Option              | Description                                      |
|---------------------|--------------------------------------------------|
| `-i`, `--input`     | Path to the Junos syslog Excel file (required)   |
| `-o`, `--output`    | Output JSON file (default: prints to screen)     |
| `-c`, `--categories`| Comma-separated categories to include            |
| `-n`, `--dry-run`   | Preview name + Grok pairs, no JSON output        |
| `--list-categories` | Print categories and exit (no input file needed) |
| `--stats`           | Show counts by category                          |
| `--graylog-version` | Graylog version string (default: `5.0.13`)       |

## How Variables Are Classified

The tool automatically picks the right Grok type for each variable:

| Variable Name Contains | Grok Type    | Example                                  |
|------------------------|--------------|------------------------------------------|
| `address` or `ip` (but not `port`) | `%{IP}`  | `source-address` → `%{IP:source_address}` |
| `port`, `count`, `packets`, `bytes`, `elapsed`, `number` | `%{NUMBER}` | `source-port` → `%{NUMBER:source_port}` |
| ends with `-id` or is `id` | `%{NUMBER}` | `session-id` → `%{NUMBER:session_id}` |
| anything else          | `%{DATA}`    | `policy-name` → `%{DATA:policy_name}`   |

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT
