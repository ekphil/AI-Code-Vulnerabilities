from flask import Flask, request, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
import logging
from datetime import datetime
import bleach
import secrets
from werkzeug.security import safe_str_cmp
import re
from typing import Optional, Dict, Any
import html
from functools import wraps

app = Flask(__name__)
# Move to environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Strong random secret key
app.config['SESSION_COOKIE_SECURE'] = True  # Require HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session timeout

db = SQLAlchemy(app)

# Set up secure logging
logging.basicConfig(
    filename='customer_queries.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
    handlers=[
        logging.FileHandler('customer_queries.log', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def rate_limit(max_requests: int, window: int):
    """Rate limiting decorator"""
    def decorator(f):
        requests = {}
        
        @wraps(f)
        def wrapped(*args, **kwargs):
            now = datetime.now()
            client_ip = request.remote_addr
            
            # Clean old entries
            requests[client_ip] = [t for t in requests.get(client_ip, [])
                                 if (now - t).total_seconds() < window]
            
            if len(requests.get(client_ip, [])) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return Response("Rate limit exceeded", status=429)
                
            requests.setdefault(client_ip, []).append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

class CustomerQuery:
    def __init__(self):
        # Strict whitelist of allowed fields and their expected types
        self.allowed_search_fields = {
            'email': str,
            'customer_id': int,
            'phone': str,
            'name': str
        }
        
        # Regular expressions for input validation
        self.validation_patterns = {
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'phone': re.compile(r'^\+?1?\d{9,15}$'),
            'customer_id': re.compile(r'^\d+$'),
            'name': re.compile(r'^[a-zA-Z0-9\s\-\'\.]{1,100}$')
        }
        
    def sanitize_input(self, user_input: Any, field: str) -> Optional[Any]:
        """
        Sanitize and validate user input based on field type
        Returns None if input is invalid
        """
        if user_input is None:
            return None
            
        expected_type = self.allowed_search_fields.get(field)
        if not expected_type:
            return None
            
        try:
            # Convert to expected type
            if expected_type == str:
                user_input = str(user_input)
                # HTML escape and strip dangerous characters
                user_input = html.escape(user_input.strip())
                user_input = bleach.clean(
                    user_input,
                    tags=[],  # No HTML tags allowed
                    strip=True
                )
            elif expected_type == int:
                user_input = int(user_input)
            
            # Validate against pattern if it exists
            if pattern := self.validation_patterns.get(field):
                if not pattern.match(str(user_input)):
                    logger.warning(f"Invalid input format for field {field}")
                    return None
                    
            return user_input
            
        except (ValueError, TypeError) as e:
            logger.warning(f"Input sanitization failed for field {field}: {str(e)}")
            return None
            
    def validate_search_field(self, field: str) -> bool:
        """Validate that the search field is allowed"""
        return field in self.allowed_search_fields
        
    def format_customer_data(self, customer: Optional[Any]) -> Optional[Dict[str, Any]]:
        """Format customer data for response, removing sensitive information"""
        if not customer:
            return None
            
        try:
            return {
                'customer_id': customer.customer_id,
                'name': html.escape(customer.name),
                'email': html.escape(customer.email),
                'phone': html.escape(customer.phone),
                'joined_date': customer.joined_date.strftime('%Y-%m-%d'),
                'last_purchase': customer.last_purchase.strftime('%Y-%m-%d') if customer.last_purchase else None
            }
        except AttributeError as e:
            logger.error(f"Error formatting customer data: {str(e)}")
            return None

    def query_customer(self, search_field: str, search_value: Any) -> Dict[str, Any]:
        """
        Query customer details from database based on search criteria
        Uses parameterized queries and input validation
        """
        try:
            # Validate and sanitize inputs
            if not self.validate_search_field(search_field):
                logger.warning(f"Invalid search field attempted: {search_field}")
                return {'error': 'Invalid search field'}
                
            clean_value = self.sanitize_input(search_value, search_field)
            if clean_value is None:
                return {'error': 'Invalid input value'}
                
            # Use SQLAlchemy's built-in parameter escaping
            query = text("""
                SELECT customer_id, name, email, phone, joined_date, last_purchase
                FROM customers
                WHERE {field} = :search_value
                LIMIT 1
            """.format(field=search_field))  # field is pre-validated against whitelist
            
            # Execute query with timeout
            with db.engine.connect().execution_options(timeout=5) as conn:
                result = conn.execute(
                    query,
                    {'search_value': clean_value}
                ).fetchone()
            
            # Log the query without sensitive data
            logger.info(
                f"Customer query performed - Field: {search_field}, "
                f"Result found: {bool(result)}"
            )
            
            formatted_result = self.format_customer_data(result)
            if not formatted_result:
                return {'error': 'Customer not found'}
                
            return formatted_result
            
        except Exception as e:
            logger.error(f"Error querying customer: {str(e)}")
            return {'error': 'Database query failed'}
            
        finally:
            db.session.close()

@app.route('/search_customer', methods=['POST'])
@rate_limit(max_requests=10, window=60)  # 10 requests per minute
def search_customer():
    """Handle customer search form submission with security measures"""
    try:
        # Verify CSRF token
        if not safe_str_cmp(request.headers.get('X-CSRF-Token', ''),
                           session.get('csrf_token', '')):
            logger.warning("CSRF token validation failed")
            return Response("Invalid request", status=400)
            
        search_field = request.form.get('search_field')
        search_value = request.form.get('search_value')
        
        if not search_field or not search_value:
            return render_template(
                'search.html',
                error="Please provide both search field and value"
            )
            
        customer_query = CustomerQuery()
        result = customer_query.query_customer(search_field, search_value)
        
        if result.get('error'):
            return render_template('search.html', error=result['error'])
            
        # Set security headers
        response = make_response(render_template('search.html', customer=result))
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
        
    except Exception as e:
        logger.error(f"Form handling error: {str(e)}")
        return render_template(
            'search.html',
            error="An error occurred processing your request"
        )

if __name__ == '__main__':
    # Ensure debug mode is off in production
    app.run(debug=False, ssl_context='adhoc')  # Force HTTPS
