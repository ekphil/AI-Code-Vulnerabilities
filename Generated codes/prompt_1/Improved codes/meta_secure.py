import sqlite3
from flask import request

def get_customer_details():
    """
    Retrieves customer details from the database based on user input.

    Returns:
        dict: Customer details (e.g., name, email, phone number)
    """

    # Validate input
    customer_id = request.form.get('customer_id')
    if not customer_id:
        return 'Invalid customer ID', 400

    # Connect to the database
    try:
        conn = sqlite3.connect('customer_database.db')
        cursor = conn.cursor()
    except sqlite3.Error as e:
        return f'Database error: {e}', 500

    # Query the database for customer details
    try:
        cursor.execute('SELECT * FROM customers WHERE customer_id=?', (customer_id,))
        customer_details = cursor.fetchone()
    except sqlite3.Error as e:
        return f'Database error: {e}', 500

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
        return 'Customer not found', 404
