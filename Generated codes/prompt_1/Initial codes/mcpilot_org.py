from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///customers.db'
db = SQLAlchemy(app)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)

@app.route('/customer', methods=['GET', 'POST'])
def get_customer():
    if request.method == 'POST':
        customer_id = request.form['customer_id']
        customer = Customer.query.filter_by(id=customer_id).first()
        if customer:
            return render_template('customer_details.html', customer=customer)
        else:
            return 'Customer not found', 404
    return render_template('customer_form.html')

if __name__ == '__main__':
    app.run(debug=True)
