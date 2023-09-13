import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, Response
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session.get("user_id")
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    stocks = db.execute("SELECT * FROM stocks WHERE userID = ?", user_id)
    updated_stocks = []
    stocks_prices = []

    for stock_data in stocks:
        # gets informarion about each stock the user has
        stock_info = lookup(stock_data["stock"])
        stock_price = stock_info["price"]
        stock_data["current_price"] = usd(stock_price)

        total_price = stock_price * stock_data["share"]
        stock_data["total_price"] = usd(total_price)
        updated_stocks.append(stock_data)

        stocks_prices.append(total_price)

    total_price = usd(sum(stocks_prices) + user_cash)

    return render_template("index.html", stocks=updated_stocks, cash=usd(user_cash), total_price=total_price)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_to_buy = request.form.get("shares")

        # Get user ID from session
        user_id = session.get("user_id")
        if user_id is None:
            return apology("User not found!", 400)

        if not shares_to_buy.isdigit():
            return apology("Invalid number of shares!")

        shares_to_buy = int(shares_to_buy)

        # Get stock quote
        quote = lookup(symbol)
        if quote is None:
            return apology("Quote not found!", 400)
        stock_price = quote["price"]

        # Deduct cash and update user's balance
        deducted_cash = shares_to_buy * stock_price
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", deducted_cash, user_id)

        # Check user's available cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        if user_cash < stock_price:
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", deducted_cash, user_id)
            return apology("Insufficient funds!", 400)

        # Check if the user already owns the stock
        existing_stock = db.execute("SELECT share FROM stocks WHERE stock = ? AND userID = ?", symbol, user_id)

        # Update or insert stock information
        if existing_stock:
            db.execute("UPDATE stocks SET share = share + ? WHERE stock = ? AND userID = ?", shares_to_buy, symbol, user_id)
        else:
            db.execute("INSERT INTO stocks (stock, share, userID) VALUES (?, ?, ?)", symbol, shares_to_buy, user_id)

        db.execute("INSERT INTO transactions (transaction_desc, shares, stock, userID) VALUES (?, ?, ?, ?)", "Buyed", shares_to_buy, symbol, user_id)

        return redirect("/")
    else:
        return render_template("buy.html")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session.get("user_id")
    transactions = db.execute("SELECT stock, shares, transaction_desc FROM transactions WHERE userID = ?", user_id)

    return render_template("history.html", transactions=transactions)


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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    """changes user password"""
    if request.method == "POST":
        new_password = request.form.get("new-password")
        confirm_password = request.form.get("confirm-new-password")

        user_id = session.get("user_id")

        # checks if the input is not blank
        if not new_password:
            return apology("must provide password", 400)

        if not confirm_password or confirm_password != new_password:
            return apology("passwords doesn't match", 400)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), user_id)

        session.clear()

        return redirect("/")
    else:
        return render_template("changePassword.html")

@app.route("/logout")
@login_required
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
        quote = lookup(request.form.get("symbol"))
        if quote:
            price = usd(quote["price"])
            return render_template("quoted.html", quote=quote, price=price)
        elif quote == None:
            return apology("quote not found!", 400)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # checks the request method
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmPassword = request.form.get("confirmation")

        user = db.execute("SELECT * FROM users WHERE username = ?", username)
        # checks if the username field is blank
        if not username:
            return apology("must provide username", 400)
        elif user:
            return apology("the username already exists", 400)
        # checks if the password field is blank
        elif not password:
            return apology("must provide password", 400)
        # checks if the confirm password field is blank, and if it is matching with the actual password
        elif not confirmPassword or password != confirmPassword:
            return apology("Confirm Password does not match the Password", 400)
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password))

            return redirect("/"), 200
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = lookup(request.form.get("symbol"))

        # Checks if is there any stock selected
        if not symbol:
            return apology("None stock selected!")
        stock_name = symbol["name"]

        shares_to_sell = request.form.get("shares")

        if not shares_to_sell.isdigit():
            return apology("Invalid number of shares!")

        shares_to_sell = int(shares_to_sell)

        # Validate shares_input
        if not shares_to_sell:
            return apology("Number of shares is required")

        # gets the id of the user in the current session
        userID = session.get("user_id")

        if not shares_to_sell or shares_to_sell < 0:
            return apology("Invalid number of shares")

        # Checks if the user has the stock
        user_stock = db.execute("SELECT * FROM stocks WHERE stock = ? AND userID = ?", stock_name, userID)
        if not user_stock:
            return apology("The user dont have this stock")

        user_shares = user_stock[0]["share"]
        # if the user has the amount of shares to sell
        if shares_to_sell > user_shares:
            return apology("User dont have enough shares!")

        # cash to be given to the user
        shares_price = int(symbol["price"]) * shares_to_sell

        # removes cash and shares from the user
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", shares_price, userID)
        db.execute("UPDATE stocks SET share = share - ? WHERE stock = ? and userID = ?", shares_to_sell, stock_name, userID)

        # checks if the user dont have the stock anymore and it deletes from the database
        stock_share = db.execute("SELECT share FROM stocks WHERE stock = ? AND userID = ?", stock_name, userID)[0]["share"]
        if stock_share == 0 or stock_share < 0:
            db.execute("DELETE FROM stocks WHERE stock = ? AND userID = ?", stock_name, userID)

        db.execute("INSERT INTO transactions (transaction_desc, shares, stock, userID) VALUES (?, ?, ?, ?)", "Sold", shares_to_sell, stock_name, userID)


        return redirect("/")

    else:
        userID = session.get("user_id")
        stocks = db.execute("SELECT * FROM stocks WHERE userID = ?", userID)

        return render_template("sell.html", stocks=stocks)
