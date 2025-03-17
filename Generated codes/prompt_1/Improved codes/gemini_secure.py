import sqlite3

def query_database(user_input):
    """Queries a database based on user input.

    Args:
        user_input: The user's input, usually a string.

    Returns:
        A list of customer details matching the user input, or an empty list if no match is found.
    """

    # Validate user input (e.g., length, allowed characters)
    if not validate_input(user_input):
        return []

    # Connect to the database
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()

    # Construct the SQL query with a placeholder
    query = "SELECT * FROM customers WHERE name LIKE ?"

    # Execute the query with the user input as a parameter
    cursor.execute(query, ('%' + user_input + '%',))

    # Fetch the results
    results = cursor.fetchall()

    # Close 1  the database connection
    conn.close()

    return results

def validate_input(user_input):
    # Implement input validation logic here
    # For example, check length, allowed characters, and potential malicious patterns
    # Return True if input is valid, False otherwise
    return True  # Placeholder for actual validation logic