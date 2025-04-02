from flask import Flask, request, jsonify, send_file
import requests
import logging
import re
import time
import io
import csv
import json
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Simple cache to store IP lookup results (IP -> data)
ip_cache = {}

# Rate limiting settings
RATE_LIMIT_CALLS = 45  # Maximum calls
RATE_LIMIT_PERIOD = 60  # Period in seconds
last_calls = []

def is_rate_limited():
    """
    Check if we're exceeding the rate limit.
    Returns True if rate-limited, False otherwise.
    """
    global last_calls
    current_time = time.time()
    
    # Remove calls older than our rate limit period
    last_calls = [call_time for call_time in last_calls if current_time - call_time < RATE_LIMIT_PERIOD]
    
    # Check if we're over the limit
    if len(last_calls) >= RATE_LIMIT_CALLS:
        return True
    
    # Add current call
    last_calls.append(current_time)
    return False

def is_valid_ip(ip):
    """
    Validate if the string is a valid IPv4 or IPv6 address.
    """
    # IPv4 pattern
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    # Basic IPv6 pattern
    ipv6_pattern = r'^[0-9a-fA-F:]+$'
    
    if re.match(ipv4_pattern, ip):
        # Additional validation for IPv4
        try:
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
    elif re.match(ipv6_pattern, ip):
        # Basic IPv6 validation
        try:
            # This is a simplistic check, urlparse does some basic validation
            parsed = urlparse(f"//{ip}")
            return True
        except Exception:
            return False
    
    return False

def get_client_ip(request):
    """
    Extract the client's IP address from the request.
    Handles X-Forwarded-For headers for proxied requests.
    """
    if 'X-Forwarded-For' in request.headers:
        # X-Forwarded-For format is client, proxy1, proxy2, ...
        forwarded_ips = request.headers.get('X-Forwarded-For', '').split(',')
        client_ip = forwarded_ips[0].strip()
        return client_ip
    return request.remote_addr

def get_ip_info(ip_address):
    """
    Fetch IP information from the IP-API service.
    Returns a dictionary with IP details or raises an exception on failure.
    """
    if is_rate_limited():
        logger.warning("Rate limit exceeded, throttling API calls.")
        time.sleep(1)  # Simple throttling by waiting a second
    
    try:
        # Use ip-api.com as our free IP geolocation service
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        # Check for API error
        if data.get('status') == 'fail':
            logger.error(f"IP API error: {data.get('message')}")
            raise ValueError(data.get('message', 'Unknown error from IP API'))
        
        # Format the response
        return {
            "ip": data.get('query'),
            "country": data.get('country'),
            "country_code": data.get('countryCode'),
            "region": data.get('regionName'),
            "region_code": data.get('region'),
            "city": data.get('city'),
            "zip": data.get('zip'),
            "location": {
                "latitude": data.get('lat'),
                "longitude": data.get('lon')
            },
            "timezone": data.get('timezone'),
            "isp": data.get('isp'),
            "organization": data.get('org'),
            "as": data.get('as')
        }
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        raise Exception(f"Failed to connect to IP lookup service: {str(e)}")
    
    except (ValueError, KeyError) as e:
        logger.error(f"Data parsing error: {str(e)}")
        raise Exception(f"Failed to parse IP information: {str(e)}")

@app.route('/api/ip', methods=['GET'])
def ip_lookup():
    """
    API endpoint to lookup IP address information.
    Returns information about the specified IP or the client's IP if none provided.
    """
    # Get IP from query parameters or use client IP
    ip_address = request.args.get('ip')
    
    if not ip_address:
        ip_address = get_client_ip(request)
        logger.debug(f"Using client IP: {ip_address}")
    
    # Validate IP address
    if not is_valid_ip(ip_address):
        return jsonify({
            "error": "Invalid IP address format",
            "status": "error"
        }), 400
    
    # Check cache
    if ip_address in ip_cache:
        logger.debug(f"Cache hit for IP: {ip_address}")
        return jsonify({
            "data": ip_cache[ip_address],
            "source": "cache",
            "status": "success"
        })
    
    # Get IP information
    try:
        ip_data = get_ip_info(ip_address)
        
        # Cache the result
        ip_cache[ip_address] = ip_data
        
        return jsonify({
            "data": ip_data,
            "status": "success"
        })
    
    except Exception as e:
        logger.error(f"Error fetching IP information: {str(e)}")
        return jsonify({
            "error": "Failed to fetch IP information",
            "details": str(e),
            "status": "error"
        }), 500

@app.route('/api/ip/download', methods=['GET'])
def download_ip_info():
    """
    Download IP information in CSV or JSON format.
    Format options: 'csv' or 'json' (default: 'json')
    """
    # Get IP from query parameters or use client IP
    ip_address = request.args.get('ip')
    format_type = request.args.get('format', 'json').lower()
    
    if not ip_address:
        ip_address = get_client_ip(request)
        logger.debug(f"Using client IP for download: {ip_address}")
    
    # Validate IP address
    if not is_valid_ip(ip_address):
        return jsonify({
            "error": "Invalid IP address format",
            "status": "error"
        }), 400
    
    # Get IP information (from cache or fresh lookup)
    try:
        if ip_address in ip_cache:
            ip_data = ip_cache[ip_address]
            logger.debug(f"Using cached data for download: {ip_address}")
        else:
            ip_data = get_ip_info(ip_address)
            # Cache the result
            ip_cache[ip_address] = ip_data
        
        # Download as CSV
        if format_type == 'csv':
            # Flatten the nested location data
            flat_data = ip_data.copy()
            if 'location' in flat_data:
                for key, value in flat_data['location'].items():
                    flat_data[f'location_{key}'] = value
                del flat_data['location']
            
            # Create CSV in memory
            csv_data = io.StringIO()
            fieldnames = flat_data.keys()
            writer = csv.DictWriter(csv_data, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(flat_data)
            
            # Create response
            csv_output = io.BytesIO(csv_data.getvalue().encode())
            csv_data.close()
            
            return send_file(
                csv_output,
                as_attachment=True,
                download_name=f"ip_info_{ip_address}.csv",
                mimetype='text/csv'
            )
        
        # Download as JSON (default)
        else:
            json_data = json.dumps(ip_data, indent=2)
            json_output = io.BytesIO(json_data.encode())
            
            return send_file(
                json_output,
                as_attachment=True,
                download_name=f"ip_info_{ip_address}.json",
                mimetype='application/json'
            )
    
    except Exception as e:
        logger.error(f"Error preparing download: {str(e)}")
        return jsonify({
            "error": "Failed to prepare download",
            "details": str(e),
            "status": "error"
        }), 500

@app.route('/api/batch', methods=['POST'])
def batch_ip_lookup():
    """
    Batch process multiple IP addresses.
    Accepts a JSON array of IP addresses and returns information for each.
    """
    try:
        # Get JSON data from request
        request_data = request.get_json()
        
        if not request_data or not isinstance(request_data, dict) or 'ips' not in request_data:
            return jsonify({
                "error": "Invalid request format. Expected JSON with 'ips' array",
                "status": "error"
            }), 400
        
        ip_list = request_data.get('ips', [])
        
        if not isinstance(ip_list, list):
            return jsonify({
                "error": "The 'ips' field must be an array",
                "status": "error"
            }), 400
        
        # Process each IP address
        results = {}
        errors = {}
        
        for ip in ip_list:
            if not isinstance(ip, str):
                errors[str(ip)] = "Not a valid string IP address"
                continue
                
            if not is_valid_ip(ip):
                errors[ip] = "Invalid IP address format"
                continue
            
            try:
                # Check cache first
                if ip in ip_cache:
                    results[ip] = ip_cache[ip]
                else:
                    ip_data = get_ip_info(ip)
                    ip_cache[ip] = ip_data
                    results[ip] = ip_data
            except Exception as e:
                errors[ip] = str(e)
        
        # Return combined results
        return jsonify({
            "results": results,
            "errors": errors,
            "status": "success",
            "total": len(ip_list),
            "successful": len(results),
            "failed": len(errors)
        })
    
    except Exception as e:
        logger.error(f"Error in batch processing: {str(e)}")
        return jsonify({
            "error": "Failed to process batch request",
            "details": str(e),
            "status": "error"
        }), 500

@app.route('/api/clear-cache', methods=['POST'])
def clear_cache():
    """Clear the IP cache (admin function)."""
    global ip_cache
    ip_cache = {}
    return jsonify({"status": "success", "message": "Cache cleared"})

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return jsonify({
        "error": "Endpoint not found",
        "status": "error"
    }), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return jsonify({
        "error": "Internal server error",
        "status": "error"
    }), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
