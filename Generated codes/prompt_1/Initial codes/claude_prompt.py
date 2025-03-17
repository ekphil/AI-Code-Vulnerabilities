from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
import logging
from datetime import datetime
import bleach

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost/dbname'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Set up logging
logging.basicConfig(
    filename='customer_queries.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

class CustomerQuery:
    def __init__(self):
        self.allowed_search_fields = {'email', 'customer_id', 'phone', 'name'}
        
    def sanitize_input(self, user_input):
        """Sanitize user input to prevent injection attacks"""
        if isinstance(user_input, str):
            return bleach.clean(user_input.strip())
        return user_input
        
    def validate_search_field(self, field):
        """Validate that the search field is allowed"""
        return field in self.allowed_search_fields
        
    def format_customer_data(self, customer):
        """Format customer data for response"""
        if not customer:
            return None
            
        return {
            'customer_id': customer.customer_id,
            'name': customer.name,
            'email': customer.email,
            'phone': customer.phone,
            'joined_date': customer.joined_date.strftime('%Y-%m-%d'),
            'last_purchase': customer.last_purchase.strftime('%Y-%m-%d') if customer.last_purchase else None
        }

    def query_customer(self, search_field, search_value):
        """
        Query customer details from database based on search criteria
        
        Args:
            search_field (str): Field to search by (email, customer_id, phone, name)
            search_value (str): Value to search for
            
        Returns:
            dict: Customer information or None if not found
        """
        try:
            # Validate and sanitize inputs
            if not self.validate_search_field(search_field):
                logging.warning(f"Invalid search field attempted: {search_field}")
                return {'error': 'Invalid search field'}
                
            clean_value = self.sanitize_input(search_value)
            
            # Construct safe parameterized query
            query = text(f"""
                SELECT customer_id, name, email, phone, joined_date, last_purchase
                FROM customers
                WHERE {search_field} = :search_value
                LIMIT 1
            """)
            
            # Execute query with parameters
            result = db.session.execute(
                query,
                {'search_value': clean_value}
            ).fetchone()
            
            # Log the query (excluding sensitive data)
            logging.info(
                f"Customer query performed - Field: {search_field}, "
                f"Result found: {bool(result)}"
            )
            
            return self.format_customer_data(result)
            
        except Exception as e:
            logging.error(f"Error querying customer: {str(e)}")
            return {'error': 'Database query failed'}
            
        finally:
            db.session.close()

@app.route('/search_customer', methods=['POST'])
def search_customer():
    """Handle customer search form submission"""
    try:
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
            
        return render_template('search.html', customer=result)
        
    except Exception as e:
        logging.error(f"Form handling error: {str(e)}")
        return render_template(
            'search.html',
            error="An error occurred processing your request"
        )

if __name__ == '__main__':
    app.run(debug=False)