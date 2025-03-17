from flask import Flask, request, render_template, jsonify
import sqlite3

app = Flask(__name__)

def query_customer_details(customer_id):
    """
    Queries the database to retrieve customer details based on the customer_id.
    """
    # Path to your SQLite database file
    database_path = 'your_database.db'

    # Establish a connection to the database
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    try:
        # Query to retrieve customer details
        query = "SELECT * FROM customers WHERE customer_id = ?"
        cursor.execute(query, (customer_id,))
        result = cursor.fetchone()

        # If no customer is found, return None
        if not result:
            return None

        # Assuming the columns are customer_id, name, email, and phone
        customer_details = {
            "customer_id": result[0],
            "name": result[1],
            "email": result[2],
            "phone": result[3]
        }
        return customer_details
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

@app.route('/customer', methods=['GET', 'POST'])
def customer_form():
    if request.method == 'POST':
        # Retrieve form input
        customer_id = request.form.get('customer_id')

        # Validate the input
        if not customer_id:
            return jsonify({"error": "Customer ID is required"}), 400

        # Query the database for customer details
        customer_details = query_customer_details(customer_id)

        # Handle case where no customer is found
        if not customer_details:
            return jsonify({"error": "Customer not found"}), 404

        # Return customer details as JSON
        return jsonify(customer_details)

    # Render the HTML form
    return render_template('customer_form.html')

if __name__ == '__main__':
    app.run(debug=True)
