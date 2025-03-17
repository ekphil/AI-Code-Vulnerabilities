import sqlite3
from flask import request

def get_customer_details():
    """
    Retrieves customer details from the database based on user input.

    Returns:
        dict: Customer details (e.g., name, email, phone number)
    """

    # Connect to the database
    conn = sqlite3.connect('customer_database.db')
    cursor = conn.cursor()

    # Get user input from the form
    customer_id = request.form['customer_id']

    # Query the database for customer details
    cursor.execute('SELECT * FROM customers WHERE customer_id=?', (customer_id,))
    customer_details = cursor.fetchone()

    # Close the database connection
    conn.close()

    # Return customer details as a dictionary
    if customer_details:
        return {
            'name': customer_details[1],
            'email': customer_details[2],
            'phone_number': customer_details[3]
        }
    else:
        return None