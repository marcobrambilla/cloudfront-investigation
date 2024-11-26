# CloudFront Log Investigation Tool

A Python tool designed for security incident investigation involving analysis of AWS CloudFront logs. Efficiently processes large volumes of log files with support for pattern matching and filtering.

## Key Features

- 🚀 Rapid processing of multiple gzipped CloudFront logs
- 🔍 Pattern matching for URLs and query parameters
- 🌍 IP geolocation with country and city information
- 💾 Memory-efficient batch processing
- 📊 Tab-separated output for easy analysis with Unix tools

## Requirements

- Python 3.7+
- Required packages: `pip install tqdm geoip2`
- MaxMind GeoLite2 City database (free account required)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cloudfront-investigation.git
cd cloudfront-investigation

# Install dependencies
pip install tqdm geoip2

# Download GeoLite2 City database and place in root directory
# Get it from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
```

## Usage

Basic usage:
```bash
python3 cloudfront_investigation.py <logs_directory> [options]
```

### Investigation Examples

Investigate specific API endpoints:
```bash
python3 cloudfront_investigation.py ./logs --url "api/v1/users"
```

Filter by query parameters:
```bash
python3 cloudfront_investigation.py ./logs --query "env=prod&user=admin"
```

Combine filters for targeted investigation:
```bash
python3 cloudfront_investigation.py ./logs --url "api/v1/.*" --query "env=prod"
```

## Output Files

The tool generates three files in the `output` directory:

| File | Description |
|------|-------------|
| `cloudfront_investigation.tsv` | Main analysis results |
| `cloudfront_investigation_ips.tsv` | IP geolocation data |
| `cloudfront_investigation.log` | Processing details and errors |

### Output Format

Main analysis file columns:
```
Source_File | Date | Time | Client_IP | URL | Query_String | Status | User_Agent
```

IP analysis file columns:
```
IP_Address | Country | City
```

## Analysis Tips

Process results with Unix tools:
```bash
# Find requests by status code
cut -f 7 output/cloudfront_investigation.tsv | sort | uniq -c

# Analyze requests from specific IPs
grep "123.45.67.89" output/cloudfront_investigation.tsv

# Count requests by URL pattern
cut -f 5 output/cloudfront_investigation.tsv | sort | uniq -c | sort -nr
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)