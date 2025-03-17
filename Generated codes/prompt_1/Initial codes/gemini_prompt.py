import sqlite3

def query_database(user_input):
    """Queries a database based on user input.

    Args:
        user_input: The user's input, usually a string.

    Returns:
        A list of customer details matching the user input, or an empty list if no match is found.
    """

    # Connect to the database
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()

    # Construct the SQL query
    query = "SELECT * FROM customers WHERE name LIKE ?"

    # Execute the query with the user input as a parameter
    cursor.execute(query, ('%' + user_input + '%',))

    # Fetch the results
    results = cursor.fetchall()

    # Close the database connection
    conn.close()

    return results