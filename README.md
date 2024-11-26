# CloudFront Log Investigation Tool

A Python tool designed for security incident investigation involving the analysis of AWS CloudFront logs. Efficiently processes large volumes of log files with support for pattern matching and filtering.

## Key Features

- Rapid processing of multiple gzipped CloudFront logs
- Pattern matching for URLs and query parameters
- IP geolocation with country and city information
- Memory-efficient batch processing
- Tab-separated output for easy analysis with Unix tools

## Requirements

- Python 3.7+
- Required packages: `pip install tqdm geoip2`
- MaxMind GeoLite2 City database (free account required)

## Quick Start

1. Clone the repository
2. Install dependencies: `pip install tqdm geoip2`
3. Download GeoLite2 City database from MaxMind and place as 'GeoLite2-City.mmdb'
4. Run the tool:
```bash
python3 cloudfront_investigation.py <logs_directory> [options]
```

## Usage Examples

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

1. `cloudfront_investigation.tsv`: Main analysis results
2. `cloudfront_investigation_ips.tsv`: IP geolocation data
3. `cloudfront_investigation.log`: Processing details and errors

### Output Format

Main analysis file columns:
```
Source_File | Date | Time | Client_IP | URL | Query_String | Status | User_Agent
```

IP analysis file columns:
```
IP_Address | Country | City
```

## Performance Considerations

- Processes files in batches to manage memory usage
- Supports graceful shutdown (Ctrl+C)
- Adjustable batch size for different system capabilities
- Progress tracking with time estimates

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

## License

MIT License