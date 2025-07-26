#!/usr/bin/env python3
"""
Wayback Machine scraper for historical data reconnaissance
Extracts URLs, endpoints, and historical data from the Internet Archive
"""

import requests
import json
import sys
import argparse
import re
import time
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Set, Optional
from datetime import datetime, timedelta
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WaybackScraper:
    """Wayback Machine scraper for security reconnaissance"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.base_url = 'https://web.archive.org'
        self.cdx_api = 'https://web.archive.org/cdx/search/cdx'
        
    def scrape_domain(self, domain: str, years_back: int = 5) -> Dict:
        """Scrape Wayback Machine data for a domain"""
        logger.info(f"Starting Wayback Machine scrape for {domain}")
        
        results = {
            'domain': domain,
            'urls': set(),
            'endpoints': set(),
            'parameters': set(),
            'subdomains': set(),
            'files': set(),
            'technologies': set(),
            'secrets': set(),
            'errors': [],
            'metadata': {
                'total_snapshots': 0,
                'date_range': {},
                'scan_date': datetime.now().isoformat()
            }
        }
        
        try:
            # Get snapshot data
            snapshots = self.get_snapshots(domain, years_back)
            results['metadata']['total_snapshots'] = len(snapshots)
            
            if snapshots:
                results['metadata']['date_range'] = {
                    'earliest': min(s['timestamp'] for s in snapshots),
                    'latest': max(s['timestamp'] for s in snapshots)
                }
            
            # Process snapshots
            for snapshot in snapshots[:1000]:  # Limit to 1000 snapshots
                try:
                    self.process_snapshot(snapshot, results)
                    time.sleep(0.1)  # Rate limiting
                except Exception as e:
                    logger.error(f"Error processing snapshot {snapshot['url']}: {e}")
                    results['errors'].append(str(e))
            
            # Extract additional data
            self.extract_endpoints(results)
            self.extract_parameters(results)
            self.extract_subdomains(results, domain)
            self.extract_interesting_files(results)
            self.detect_technologies(results)
            self.find_secrets(results)
            
        except Exception as e:
            logger.error(f"Error scraping domain {domain}: {e}")
            results['errors'].append(str(e))
        
        # Convert sets to lists for JSON serialization
        for key in ['urls', 'endpoints', 'parameters', 'subdomains', 'files', 'technologies', 'secrets']:
            results[key] = list(results[key])
        
        logger.info(f"Wayback scrape completed for {domain}. Found {len(results['urls'])} URLs")
        return results
    
    def get_snapshots(self, domain: str, years_back: int) -> List[Dict]:
        """Get snapshots from Wayback Machine CDX API"""
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=years_back * 365)
        
        params = {
            'url': f'{domain}/*',
            'matchType': 'prefix',
            'collapse': 'urlkey',
            'output': 'json',
            'fl': 'original,mimetype,timestamp,endtimestamp,groupcount,uniqcount',
            'filter': '!statuscode:404',
            'from': start_date.strftime('%Y%m%d'),
            'to': end_date.strftime('%Y%m%d'),
            'limit': 10000
        }
        
        try:
            response = self.session.get(self.cdx_api, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if not data:
                return []
            
            # Skip header row
            headers = data[0]
            snapshots = []
            
            for row in data[1:]:
                snapshot = dict(zip(headers, row))
                snapshots.append(snapshot)
            
            return snapshots
            
        except Exception as e:
            logger.error(f"Error fetching snapshots: {e}")
            return []
    
    def process_snapshot(self, snapshot: Dict, results: Dict):
        """Process individual snapshot"""
        
        url = snapshot.get('original', '')
        if not url:
            return
        
        results['urls'].add(url)
        
        # Parse URL components
        parsed = urlparse(url)
        
        # Extract subdomain
        if parsed.hostname:
            results['subdomains'].add(parsed.hostname)
        
        # Extract path
        if parsed.path and parsed.path != '/':
            results['endpoints'].add(parsed.path)
        
        # Extract query parameters
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    results['parameters'].add(param_name)
        
        # Check for interesting file extensions
        if '.' in parsed.path:
            ext = parsed.path.split('.')[-1].lower()
            if ext in ['js', 'css', 'json', 'xml', 'txt', 'config', 'env', 'bak', 'old']:
                results['files'].add(url)
    
    def extract_endpoints(self, results: Dict):
        """Extract API endpoints and interesting paths"""
        
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/rest/',
            r'/service/',
            r'/endpoint/',
            r'/ajax/',
            r'/json/',
            r'/xml/',
        ]
        
        for url in results['urls']:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            for pattern in api_patterns:
                if re.search(pattern, path):
                    results['endpoints'].add(parsed.path)
                    break
    
    def extract_parameters(self, results: Dict):
        """Extract common parameters from URLs"""
        
        param_counts = {}
        
        for url in results['urls']:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        param_name = param.split('=')[0]
                        param_counts[param_name] = param_counts.get(param_name, 0) + 1
        
        # Add frequently used parameters
        for param, count in param_counts.items():
            if count > 1:  # Parameter appears in multiple URLs
                results['parameters'].add(param)
    
    def extract_subdomains(self, results: Dict, main_domain: str):
        """Extract subdomains"""
        
        subdomain_pattern = rf'([a-zA-Z0-9\-]+\.)*{re.escape(main_domain)}'
        
        for url in results['urls']:
            parsed = urlparse(url)
            if parsed.hostname and parsed.hostname.endswith(main_domain):
                results['subdomains'].add(parsed.hostname)
    
    def extract_interesting_files(self, results: Dict):
        """Extract interesting files and directories"""
        
        interesting_patterns = [
            r'\.env',
            r '\.config',
            r'\.bak',
            r'\.old',
            r'\.backup',
            r'\.sql',
            r'\.dump',
            r'config\.',
            r'admin',
            r'test',
            r'dev',
            r'staging',
            r'debug',
            r'logs?/',
            r'tmp/',
            r'temp/',
            r'backup/',
        ]
        
        for url in results['urls']:
            url_lower = url.lower()
            for pattern in interesting_patterns:
                if re.search(pattern, url_lower):
                    results['files'].add(url)
                    break
    
    def detect_technologies(self, results: Dict):
        """Detect technologies from URL patterns"""
        
        tech_patterns = {
            'WordPress': [r'/wp-content/', r'/wp-admin/', r'/wp-includes/'],
            'Drupal': [r'/sites/default/', r'/modules/', r'/themes/'],
            'Joomla': [r'/administrator/', r'/components/', r'/modules/'],
            'PHP': [r'\.php'],
            'ASP.NET': [r'\.aspx?', r'/App_Data/'],
            'Java': [r'\.jsp', r'\.do', r'/WEB-INF/'],
            'Python': [r'\.py', r'/django/', r'/flask/'],
            'Ruby': [r'\.rb', r'/rails/'],
            'Node.js': [r'/node_modules/', r'\.js$'],
        }
        
        for tech, patterns in tech_patterns.items():
            for url in results['urls']:
                url_lower = url.lower()
                for pattern in patterns:
                    if re.search(pattern, url_lower):
                        results['technologies'].add(tech)
                        break
    
    def find_secrets(self, results: Dict):
        """Find potential secrets and sensitive information in URLs"""
        
        secret_patterns = [
            r'api[_\-]?key',
            r'secret[_\-]?key',
            r'access[_\-]?token',
            r'auth[_\-]?token',
            r'session[_\-]?id',
            r'password',
            r'passwd',
            r'pwd',
            r'private[_\-]?key',
            r'client[_\-]?secret',
            r'aws[_\-]?key',
            r'google[_\-]?key',
            r'facebook[_\-]?key',
        ]
        
        for url in results['urls']:
            url_lower = url.lower()
            for pattern in secret_patterns:
                if re.search(pattern, url_lower):
                    results['secrets'].add(url)
                    break
    
    def get_snapshot_content(self, url: str, timestamp: str) -> Optional[str]:
        """Get content of a specific snapshot"""
        
        wayback_url = f"{self.base_url}/web/{timestamp}/{url}"
        
        try:
            response = self.session.get(wayback_url, timeout=15)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            logger.error(f"Error fetching snapshot content: {e}")
        
        return None
    
    def search_content(self, domain: str, search_terms: List[str]) -> Dict:
        """Search for specific terms in snapshot content"""
        
        results = {
            'domain': domain,
            'search_terms': search_terms,
            'matches': [],
            'snapshots_searched': 0
        }
        
        # Get recent snapshots
        snapshots = self.get_snapshots(domain, 2)  # Last 2 years
        
        for snapshot in snapshots[:50]:  # Limit to 50 snapshots
            try:
                content = self.get_snapshot_content(
                    snapshot['original'], 
                    snapshot['timestamp']
                )
                
                if content:
                    results['snapshots_searched'] += 1
                    
                    for term in search_terms:
                        if term.lower() in content.lower():
                            results['matches'].append({
                                'url': snapshot['original'],
                                'timestamp': snapshot['timestamp'],
                                'term': term,
                                'context': self.extract_context(content, term)
                            })
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Error searching snapshot content: {e}")
        
        return results
    
    def extract_context(self, content: str, term: str, context_length: int = 100) -> str:
        """Extract context around a search term"""
        
        content_lower = content.lower()
        term_lower = term.lower()
        
        index = content_lower.find(term_lower)
        if index == -1:
            return ""
        
        start = max(0, index - context_length)
        end = min(len(content), index + len(term) + context_length)
        
        context = content[start:end]
        
        # Clean up context
        context = re.sub(r'\s+', ' ', context)
        context = context.strip()
        
        return context
    
    def find_urls_by_extension(self, domain: str, extensions: List[str]) -> List[str]:
        """Find URLs with specific file extensions"""
        
        found_urls = []
        snapshots = self.get_snapshots(domain, 5)
        
        for snapshot in snapshots:
            url = snapshot.get('original', '')
            parsed = urlparse(url)
            
            if '.' in parsed.path:
                file_ext = parsed.path.split('.')[-1].lower()
                if file_ext in extensions:
                    found_urls.append(url)
        
        return list(set(found_urls))  # Remove duplicates
    
    def get_domain_history(self, domain: str) -> Dict:
        """Get historical information about a domain"""
        
        snapshots = self.get_snapshots(domain, 10)  # 10 years back
        
        if not snapshots:
            return {'domain': domain, 'history': []}
        
        # Group by year
        history_by_year = {}
        
        for snapshot in snapshots:
            timestamp = snapshot['timestamp']
            year = timestamp[:4]
            
            if year not in history_by_year:
                history_by_year[year] = {
                    'year': year,
                    'snapshot_count': 0,
                    'unique_urls': set(),
                    'technologies': set()
                }
            
            history_by_year[year]['snapshot_count'] += 1
            history_by_year[year]['unique_urls'].add(snapshot['original'])
        
        # Convert to list and sort
        history = []
        for year_data in history_by_year.values():
            year_data['unique_urls'] = len(year_data['unique_urls'])
            year_data.pop('technologies')  # Remove sets for JSON serialization
            history.append(year_data)
        
        history.sort(key=lambda x: x['year'])
        
        return {
            'domain': domain,
            'total_snapshots': len(snapshots),
            'date_range': {
                'earliest': min(s['timestamp'] for s in snapshots),
                'latest': max(s['timestamp'] for s in snapshots)
            },
            'history': history
        }

def main():
    parser = argparse.ArgumentParser(description='Wayback Machine scraper for security reconnaissance')
    parser.add_argument('--domain', required=True, help='Domain to scrape')
    parser.add_argument('--years', type=int, default=5, help='Years back to search')
    parser.add_argument('--search-terms', nargs='+', help='Terms to search in content')
    parser.add_argument('--extensions', nargs='+', help='File extensions to find')
    parser.add_argument('--history', action='store_true', help='Get domain history')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    scraper = WaybackScraper()
    
    try:
        if args.search_terms:
            results = scraper.search_content(args.domain, args.search_terms)
        elif args.extensions:
            urls = scraper.find_urls_by_extension(args.domain, args.extensions)
            results = {'domain': args.domain, 'urls': urls}
        elif args.history:
            results = scraper.get_domain_history(args.domain)
        else:
            results = scraper.scrape_domain(args.domain, args.years)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"Results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2, default=str))
    
    except Exception as e:
        logger.error(f"Error in wayback scraper: {e}")
        error_result = {'error': str(e), 'success': False}
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == '__main__':
    main()
