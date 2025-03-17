import os
from flask import Flask, request, render_template, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import logging

app = Flask(__name__)

# Use environment variables for configuration
DATABASE_PATH = os.getenv('DATABASE_PATH', 'your_database.db')
DEBUG_MODE = os.getenv('FLASK_DEBUG', 'False') == 'True'

# Set up rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def query_customer_details(customer_id):
    """
    Queries the database to retrieve customer details based on the customer_id.
    """
    conn = None
    try:
        # Validate that customer_id is numeric
        if not customer_id.isdigit():
            logger.warning(f"Invalid Customer ID format: {customer_id}")
            return None

        # Connect to the database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Query the database using a parameterized query
        query = "SELECT customer_id, name, email, phone FROM customers WHERE customer_id = ?"
        cursor.execute(query, (customer_id,))
        result = cursor.fetchone()

        # If no customer is found, return None
        if not result:
            return None

        # Map results to a dictionary
        customer_details = {
            "customer_id": result[0],
            "name": result[1],
            "email": result[2],
            "phone": result[3]
        }
        return customer_details
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return None
    finally:
        if conn:
            conn.close()

@app.route('/customer', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit specific to this route
def customer_form():
    if request.method == 'POST':
        customer_id = request.form.get('customer_id', '').strip()

        # Validate input
        if not customer_id or not customer_id.isdigit() or len(customer_id) > 10:
            logger.warning("Invalid input for customer ID")
            return jsonify({"error": "Invalid Customer ID"}), 400

        # Query the database for customer details
        customer_details = query_customer_details(customer_id)

        # Handle case where no customer is found
        if not customer_details:
            return jsonify({"error": "Customer not found"}), 404

        # Return customer details as JSON with proper Content-Type
        return jsonify(customer_details), 200

    # Render the HTML form (safe content rendering with Jinja2)
    return render_template('customer_form.html')

@app.after_request
def set_security_headers(response):
    """
    Add security headers to every response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=()'
    return response

if __name__ == '__main__':
    app.run(debug=DEBUG_MODE)
