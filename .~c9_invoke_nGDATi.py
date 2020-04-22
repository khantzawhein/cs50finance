import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
import requests
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    dataDB = db.execute("select name,symbol,sum(quantity) as quantity,(SELECT price FROM shares AS s2 WHERE s2.user_id = s.user_id and s2.symbol = s.symbol ORDER BY id DESC LIMIT 1) as price FROM shares AS s WHERE s.user_id = ? GROUP BY symbol", session['user_id']);
    total_value= 0.0 + session['current_cash']
    for row in dataDB:
        total_value += (row['quantity'] * row['price'])
    return render_template("index.html", dataRows=dataDB, cash=usd(session['current_cash']), total_value=usd(total_value), usd=usd)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get('shares'))
        quoteData = lookup(symbol)
        price = quoteData['price']
        name = quoteData['name']
        totalCost = (shares*price)

        if quoteData:
            if totalCost > session['current_cash']:
                return apology('Can\'t Afford', 400)

            db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=(session['current_cash']-totalCost), id=session['user_id'])
            db.execute("INSERT INTO shares (user_id,name, symbol, quantity, price) VALUES (?, ?, ?, ?, ?)",
            session['user_id'], name, symbol, shares, price)
            flash(f"Bought ")
            return redirect("/")
        else:
            flash("Symbol not found, please try again")
            return render_template("buy.html")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        session["username"] = request.form.get("username")
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=session["username"])

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        cash_rows = db.execute("SELECT cash FROM users WHERE id = :id", id=session['user_id'])
        session['current_cash'] = cash_rows[0]['cash']
        flash(f"You are logged in as {session['username']}")
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        session['quoteData'] = lookup(request.form.get("symbol"))
        if session['quoteData']:
            return render_template("quoted.html", name = session['quoteData']['name'], price = usd(session['quoteData']['price']), symbol = session['quoteData']['symbol'])
        else:
            return apology("Invaild Symbol")
    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        if not check_user(username):
            flash("This username is already taken")
            return render_template("register.html")
        if not password:
            return apology("missing password", 400)
        if not confirm:
            return apology("missing confirm password", 400)
        if not password == confirm:
            return apology("mismatch password", 400)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash = generate_password_hash(password))
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        flash(f"You are logged in as {username}")
        return redirect("/")
    else:
        return render_template("register.html")

def check_user(username):
    """Check username in database"""
    rows = db.execute("SELECT username FROM users WHERE username = ?", username)
    if len(rows) > 0 or username == "":
        return False
    else:
        return True

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quantity = int(request.form.get("shares"))
        lookupData = lookup(symbol)
        price = lookupData["price"]
        rows = db.execute("SELECT sum(quantity) as quantity FROM shares WHERE user_id = ? AND symbol = ? GROUP BY symbol;",session['user_id'], symbol)
        if rows[0]['quantity'] < quantity:
            return apology("Too Many Shares")
        elif quantity < 0:
            return apology("Invalid Number")
        quantityRow = db.execute("SELECT quantity FROM shares WHERE user_id = ? and symbol = ? LIMIT 1",session["user_id"], symbol)
        if not (quantity - quantityRow[0]['quantity']) == 0:
            db.execute("INSERT INTO shares (user_id,name, symbol, quantity, price) VALUES (:user_id, :name, :symbol, :quantity, :price, )", user_id=session["user_id"], name=lookupData["name"], symbol=lookupData["symbol"], quantity=(-quantity), price=lookupData["price"])
        flash("Successfully sold!")
        return redirect("/")

    else:
        rows = db.execute("SELECT DISTINCT symbol FROM shares WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", rows=rows)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
