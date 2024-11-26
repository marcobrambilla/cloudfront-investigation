#!/usr/bin/env python3

"""
CloudFront Log Investigation
Analyzes CloudFront logs from local .gz files with support for URL and query parameter filtering.
Outputs results in tab-separated format for easy processing with Unix tools.

Example usage:
    # Find URLs containing 'api/v1/users'
    python3 cloudfront_analyzer.py ./logs --url "api/v1/users"
    
    # Find requests with specific query parameters
    python3 cloudfront_analyzer.py ./logs --query "user:john.*,type:premium"
    
    # Combine URL and query parameter filtering
    python3 cloudfront_analyzer.py ./logs --url "api/v1/.*" --query "user:john.*"
"""

from typing import List, Dict, Optional, Generator, Iterator, Union
from dataclasses import dataclass
import gzip
import logging
from pathlib import Path
import sys
import asyncio
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import time
from datetime import datetime
import csv
from tqdm import tqdm
import signal
import os
import urllib.parse
import re
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import geoip2.database
from geoip2.errors import AddressNotFoundError

# Create output directory if it doesn't exist
Path('output').mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='output/cloudfront_investigation.log'
)
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

@dataclass
class CloudFrontLogEntry:
    """Represents a single CloudFront log entry with essential fields."""
    date: str
    time: str
    edge_location: str
    client_ip: str
    uri_stem: str
    status: str
    user_agent: str
    query_string: str
    source_file: str
    
    @property
    def full_url(self) -> str:
        """Get the full URL including query parameters."""
        if self.query_string:
            return f"{self.uri_stem}?{self.query_string}"
        return self.uri_stem
    
    def get_query_params(self) -> Dict[str, List[str]]:
        """Parse and return query parameters as a dictionary."""
        if not self.query_string:
            return {}
        return urllib.parse.parse_qs(self.query_string)
    
    @classmethod
    def from_log_line(cls, line: str, source_file: str) -> Optional['CloudFrontLogEntry']:
        """Create a CloudFrontLogEntry from a tab-delimited log line."""
        try:
            fields = line.strip().split('\t')
            return cls(
                source_file=source_file,
                date=fields[0],
                time=fields[1],
                edge_location=fields[2],
                client_ip=fields[4],
                uri_stem=fields[7],
                status=fields[8],
                user_agent=fields[10],
                query_string=fields[11]
            )
        except (IndexError, ValueError) as e:
            return None

class URLFilter:
    """Handles URL and query parameter filtering."""
    
    def __init__(self, url_patterns: List[str] = None, query_params: str = None):
        """
        Initialize URL filter.
        
        Args:
            url_patterns: List of URL patterns to match (supports regex)
            query_params: Query string format to match
        """
        self.url_patterns = [re.compile(pattern) for pattern in (url_patterns or [])]
        
        # Parse query string format into dict of patterns
        self.query_params = {}
        if query_params:
            for param in query_params.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    self.query_params[key] = [re.compile(f"^{value}$")]
                else:
                    logger.warning(f"Ignoring invalid query parameter format: {param}")
    
    def matches(self, entry: CloudFrontLogEntry) -> bool:
        """Check if the log entry matches the filter criteria."""
        entry_params = entry.get_query_params()
        
        # Debug every line's parameters and match result
        logger.debug(f"Checking line - Query params: {entry_params}")
        
        # If no filters are set, match everything
        if not self.url_patterns and not self.query_params:
            logger.debug("No filters set - MATCH")
            return True
            
        # Check URL patterns
        url_match = not self.url_patterns or any(
            pattern.search(entry.full_url)
            for pattern in self.url_patterns
        )
        
        # Check query parameters
        if not self.query_params:
            result = url_match
            logger.debug(f"URL only check - {'MATCH' if result else 'NO MATCH'}")
            return result
        
        param_match = all(
            any(pattern.search(value)
                for pattern in patterns
                for param_value in entry_params.get(param_name, [])
                for value in ([param_value] if isinstance(param_value, str) else param_value))
            for param_name, patterns in self.query_params.items()
        )
        
        result = url_match and param_match
        logger.debug(f"Final result - {'MATCH' if result else 'NO MATCH'}")
        return result

class BatchCloudFrontAnalyzer:
    """Analyzes CloudFront logs in batches with URL and query parameter filtering."""
    
    def __init__(self, logs_directory: Path, batch_size: int = 10):
        """
        Initialize the analyzer.
        
        Args:
            logs_directory: Path to directory containing .gz log files
            batch_size: Number of files to process simultaneously
        """
        self.logs_directory = Path(logs_directory)
        self.batch_size = batch_size
        self.executor = ThreadPoolExecutor(max_workers=batch_size)
        self.stop_requested = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
    
    def handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print("\nShutdown requested. Completing current batch...")
        self.stop_requested = True
    
    def get_log_files(self) -> List[Path]:
        """Get all .gz files sorted by name."""
        return sorted(self.logs_directory.glob("*.gz"))
    
    def group_into_batches(self, files: List[Path]) -> Generator[List[Path], None, None]:
        """Group files into batches for processing."""
        for i in range(0, len(files), self.batch_size):
            yield files[i:i + self.batch_size]
    
    async def process_log_file(self, file_path: Path, url_filter: URLFilter) -> List[CloudFrontLogEntry]:
        """Process a single log file and return matching entries."""
        try:
            matches = []
            total_lines = 0
            skipped_lines = 0
            parse_errors = 0
            
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='replace') as gz_file:
                for line in gz_file:
                    total_lines += 1
                    if self.stop_requested:
                        break
                    if line.startswith('#'):
                        skipped_lines += 1
                        continue
                    
                    entry = CloudFrontLogEntry.from_log_line(line, file_path.name)
                    if not entry:
                        parse_errors += 1
                        continue
                    
                    # Debug each potential match
                    params = entry.get_query_params()
                    if 'env' in params:
                        logger.debug(f"Line {total_lines}: Found query params: {params}")
                        logger.debug(f"URL: {entry.uri_stem}")
                        if not url_filter.matches(entry):
                            logger.debug(f"Failed to match filter. Query string: {entry.query_string}")
                    
                    if url_filter.matches(entry):
                        matches.append(entry)
            
            logger.info(f"File stats for {file_path}:")
            logger.info(f"  Total lines: {total_lines}")
            logger.info(f"  Skipped comments: {skipped_lines}")
            logger.info(f"  Parse errors: {parse_errors}")
            logger.info(f"  Matches found: {len(matches)}")
            return matches
        
        except Exception as e:
            logger.error(f"Error processing {file_path}: {str(e)}")
            return []
    
    def write_batch_results(self, results: List[CloudFrontLogEntry], output_file: Path, 
                          write_header: bool = False):
        """Write batch results to tab-separated file."""
        mode = 'w' if write_header else 'a'
        with open(output_file, mode, newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_MINIMAL)
            if write_header:
                writer.writerow([
                    'Source_File', 'Date', 'Time', 'Client_IP', 'URL', 'Query_String',
                    'Status', 'User_Agent'
                ])
            
            for entry in results:
                writer.writerow([
                    entry.source_file,
                    entry.date,
                    entry.time,
                    entry.client_ip,
                    entry.uri_stem,
                    entry.query_string or '-',
                    entry.status,
                    entry.user_agent.replace('\t', ' ')
                ])
    
    async def analyze_logs(self, url_filter: URLFilter, output_file: Path):
        """Analyze log files in batches."""
        # Create output directory if it doesn't exist
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)
        
        # Update output file path to be in output directory
        output_file = output_dir / output_file.name
        
        log_files = self.get_log_files()
        total_files = len(log_files)
        
        if total_files == 0:
            logger.error(f"No .gz files found in {self.logs_directory}")
            return
        
        logger.info(f"Found {total_files} log files to process")
        print(f"\nProcessing {total_files} files in batches of {self.batch_size}")
        
        total_matches = 0
        processed_files = 0
        start_time = time.time()
        
        with tqdm(total=total_files, desc="Processing files") as pbar:
            for batch in self.group_into_batches(log_files):
                if self.stop_requested:
                    break
                
                tasks = [self.process_log_file(file_path, url_filter) 
                        for file_path in batch]
                batch_results = await asyncio.gather(*tasks)
                
                batch_matches = [entry for file_matches in batch_results 
                               for entry in file_matches]
                self.write_batch_results(
                    batch_matches,
                    output_file,
                    write_header=(processed_files == 0)
                )
                
                total_matches += len(batch_matches)
                processed_files += len(batch)
                pbar.update(len(batch))
                
                elapsed_time = time.time() - start_time
                avg_time_per_file = elapsed_time / processed_files if processed_files > 0 else 0
                remaining_files = total_files - processed_files
                estimated_remaining_time = remaining_files * avg_time_per_file
                
                logger.info(
                    f"Batch completed: {len(batch_matches)} matches found. "
                    f"Total matches so far: {total_matches}. "
                    f"Estimated time remaining: {estimated_remaining_time:.1f}s"
                )
        
        total_time = time.time() - start_time
        logger.info(f"\nAnalysis completed in {total_time:.1f}s")
        logger.info(f"Total matches found: {total_matches}")
        logger.info(f"Results written to: {output_file}")
        
        # After processing all files, write unique IPs
        self.write_unique_ips(output_file, Path('output') / 'cloudfront_investigation_ips.tsv')
    
    def write_unique_ips(self, input_file: Path, output_file: Path):
        """Extract unique IPs from analysis results and write to file with geolocation."""
        # Update output file path to be in output directory
        output_file = Path('output') / 'cloudfront_investigation_ips.tsv'
        
        unique_ips = set()
        
        # Collect unique IPs
        with open(input_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter='\t')
            next(reader)  # Skip header
            for row in reader:
                unique_ips.add(row[3])  # Client_IP is the 4th column
        
        # Write IPs with geolocation
        try:
            with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f, delimiter='\t')
                    writer.writerow(['IP_Address', 'Country', 'City'])
                    
                    for ip in sorted(unique_ips):
                        try:
                            response = reader.city(ip)
                            country = response.country.name or 'Unknown'
                            city = response.city.name or 'Unknown'
                        except (AddressNotFoundError, ValueError):
                            country = 'Unknown'
                            city = 'Unknown'
                        
                        writer.writerow([ip, country, city])
        
            logger.info(f"Found {len(unique_ips)} unique IP addresses")
            logger.info(f"IP geolocation data written to: {output_file}")
        except Exception as e:
            logger.error(f"Error processing IP geolocation: {str(e)}")

def parse_query_params(param_str: str) -> Dict[str, List[str]]:
    """Parse query parameter patterns from command line argument."""
    if not param_str:
        return {}
    
    params = {}
    for param in param_str.split(','):
        if ':' in param:
            key, patterns = param.split(':', 1)
            params[key] = patterns.split('|')
        else:
            params[param] = ['.*']
    return params

async def main():
    """Main entry point for the script."""
    parser = ArgumentParser(
        description='''
        CloudFront Log Analyzer with URL and Query Parameter Filtering
        
        Examples:
          # Find URLs containing 'api/v1/users'
          python3 cloudfront_analyzer.py ./logs --url "api/v1/users"
          
          # Find requests with specific query parameters
          python3 cloudfront_analyzer.py ./logs --query "user:john.*,type:premium"
          
          # Combine URL and query parameter filtering
          python3 cloudfront_analyzer.py ./logs --url "api/v1/.*" --query "user:john.*"
        ''',
        formatter_class=RawDescriptionHelpFormatter
    )
    
    parser.add_argument('logs_directory', type=str,
                       help='Directory containing .gz log files')
    parser.add_argument('--url', type=str, action='append',
                       help='URL pattern to match (can be specified multiple times)')
    parser.add_argument('--query', type=str,
                       help='Query parameter patterns (format: param:pattern|pattern,...)')
    parser.add_argument('--output', type=str, default='output/cloudfront_investigation.tsv',
                       help='Output TSV file path')
    parser.add_argument('--batch-size', type=int, default=10,
                       help='Number of files to process simultaneously')
    
    args = parser.parse_args()
    
    logs_directory = Path(args.logs_directory)
    if not logs_directory.exists():
        print(f"Error: Directory not found: {logs_directory}")
        sys.exit(1)
    
    url_filter = URLFilter(
        url_patterns=args.url,
        query_params=args.query
    )
    
    analyzer = BatchCloudFrontAnalyzer(
        logs_directory,
        batch_size=min(args.batch_size, max(1, os.cpu_count() or 2))
    )
    
    try:
        await analyzer.analyze_logs(url_filter, Path(args.output))
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
    