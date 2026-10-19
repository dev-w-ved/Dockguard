from flask import Flask, request
import os
import sqlite3

app = Flask(__name__)
DATABASE_URL = "sqlite:///tmp/orders.db"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

@app.get("/orders")
def orders():
    customer = request.args.get("customer", "")
    query = "SELECT * FROM orders WHERE customer = '" + customer + "'"
    return {"rows": sqlite3.connect("orders.db").execute(query).fetchall()}

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
