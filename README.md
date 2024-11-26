# CloudFront Log Analyzer

A Python tool for analyzing AWS CloudFront logs from local gzipped files. This tool efficiently processes large numbers of log files with support for URL pattern matching and query parameter filtering.

## Features

- Process multiple gzipped CloudFront logs efficiently
- Filter by URL patterns using regular expressions
- Filter by query parameters and their values
- Memory-efficient batch processing
- Progress tracking with time estimates
- Tab-separated output format for Unix tool compatibility
- Graceful shutdown handling
- Detailed logging

## Requirements

- Python 3.7 or higher
- Required Python packages:
  ```bash
  pip install tqdm
  ```

## Installation

1. Save the script as `cloudfront_analyzer.py`
2. Make it executable:
   ```bash
   chmod +x cloudfront_analyzer.py
   ```

## Usage

### Basic Command Format

```bash
python3 cloudfront_analyzer.py <logs_directory> [options]
```

### Command Line Options

- `logs_directory`: Directory containing .gz log files (required)
- `--url PATTERN`: URL pattern to match (can be specified multiple times)
- `--query PARAMS`: Query parameter patterns
- `--output FILE`: Output TSV file path (default: cloudfront_analysis.tsv)
- `--batch-size N`: Number of files to process simultaneously (default: 10)

### Examples

1. Find URLs containing a specific pattern:
   ```bash
   python3 cloudfront_analyzer.py ./logs --url "api/v1/users"
   ```

2. Find requests with specific query parameters:
   ```bash
   python3 cloudfront_analyzer.py ./logs --query "user:john.*,type:premium"
   ```

3. Combine URL and query parameter filtering:
   ```bash
   python3 cloudfront_analyzer.py ./logs --url "api/v1/.*" --query "user:john.*"
   ```

4. Specify custom output file and batch size:
   ```bash
   python3 cloudfront_analyzer.py ./logs --url "api/v1/.*" --output results.tsv --batch-size 20
   ```

### Query Parameter Pattern Format

The query parameter pattern uses the format:
```
param1:pattern1|pattern2,param2:pattern3
```

Where:
- Multiple parameters are separated by commas
- Multiple patterns for the same parameter are separated by |
- Patterns support regular expressions

Examples:
- `user:john.*`: Match 'user' parameter starting with 'john'
- `type:premium|trial`: Match 'type' parameter being either 'premium' or 'trial'
- `user:john.*,type:premium`: Match both conditions

## Timestamps and Time Zones

CloudFront logs use UTC (Coordinated Universal Time) for all timestamps. This means:
- The `Date` field is in UTC
- The `Time` field is in UTC/GMT (24-hour format)
- No timezone conversion is performed by default
- When correlating with local events, remember to convert from UTC to your local timezone

For example, a log entry with:
```
Date: 2024-03-15
Time: 12:34:56
```
Represents 12:34:56 PM UTC on March 15, 2024. To convert to your local timezone:
- US Eastern (UTC-4): 8:34:56 AM EDT
- US Pacific (UTC-7): 5:34:56 AM PDT
- Central Europe (UTC+1): 1:34:56 PM CET

## Output Format

The tool generates a tab-separated file with the following columns:

1. Date
2. Time
3. Client_IP
4. URL
5. Query_String
6. Status
7. User_Agent

Example output:
```
Date    Time        Client_IP       URL             Query_String    Status  User_Agent
2024-03-15      12:34:56        123.45.67.89       /api/v1/users   id=123&type=premium        200     Mozilla/5.0
2024-03-15      12:35:02        123.45.67.90       /api/v1/profile user=john&view=full        200     Mozilla/5.0
```

## Processing Large Log Sets

The tool is optimized for processing large sets of log files:

- Files are processed in batches to manage memory usage
- Progress bar shows completion status and estimated time remaining
- Results are written to disk after each batch
- Graceful shutdown with Ctrl+C (completes current batch before exiting)

## Working with Results

You can process the tab-separated output using standard Unix tools:

```bash
# View first few lines
head -n 5 results.tsv

# Count requests by status code
cut -f 6 results.tsv | sort | uniq -c

# Find all requests from a specific IP
grep "123.45.67.89" results.tsv

# Count requests by URL
cut -f 4 results.tsv | sort | uniq -c | sort -nr
```

## Logging

The tool logs its activity to both console and a log file:

- Console: Shows progress bar and batch completion updates
- Log file: `cloudfront_analysis.log` contains detailed processing information

## Error Handling

- Invalid log lines are skipped and logged
- Processing continues even if individual files fail
- Graceful shutdown support (Ctrl+C)
- Detailed error logging to `cloudfront_analysis.log`

## Performance Tips

1. Adjust batch size based on your system:
   ```bash
   # For systems with more CPU cores
   python3 cloudfront_analyzer.py ./logs --batch-size 20
   ```

2. For very large log sets, process in date ranges:
   ```bash
   # Move logs to dated directories first
   mkdir logs_january
   mv E1KX122RMFP5QM.2024-01-*.gz logs_january/
   
   # Process each directory separately
   python3 cloudfront_analyzer.py ./logs_january --url "api/v1/users"
   ```

## Limitations

- Processes only gzipped CloudFront logs (.gz files)
- Requires all log files to be in standard CloudFront log format
- Memory usage scales with batch size and number of matching entries

## Troubleshooting

1. If the script seems slow:
   - Reduce batch size
   - Ensure enough free memory is available
   - Use more specific URL or query patterns

2. If you see memory errors:
   - Reduce batch size
   - Process fewer files at once
   - Use more specific filters

3. If results are unexpected:
   - Check regular expression patterns
   - Look at the log file for skipped entries
   - Verify log file format matches CloudFront standard

## Contributing

Feel free to submit issues and enhancement requests!

## License

This tool is released under the MIT License.