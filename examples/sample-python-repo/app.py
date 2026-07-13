"""Sample app with intentional bugs for STCA pipeline testing.

Each function has a documented bug that one of the STCA layers should catch.
"""


def process_payment(amount: float, card_number: str):
    """Process a payment. BUGS:
    - L0/SAST: card_number logged via print() (L5 policy violation)
    - L0/SAST: amount could be negative (no guard)
    - L3 invariant: amount should be positive
    """
    print(f"Processing payment for card {card_number}")
    if amount < 0:
        return None
    # BUG: SQL injection — using f-string in execute()
    query = f"INSERT INTO payments (amount, card) VALUES ({amount}, '{card_number}')"
    return query


def calculate_discount(price: float, discount_percent: float) -> float:
    """Calculate discounted price. BUGS:
    - L3 invariant: price should be non-negative
    - L3 invariant: discount_percent should be in [0, 100]
    - Off-by-one if discount_percent > 100 (no guard)
    """
    if price < 0:
        raise ValueError("price must be non-negative")
    return price * (1 - discount_percent / 100)


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate a user. BUGS:
    - L0/SAST: hardcoded password check (insecure)
    - L0/secrets: password compared to hardcoded value
    - L5 policy: password in log statement
    """
    if password == "admin123":
        print(f"User {username} authenticated with password {password}")
        return True
    return False


def parse_config(config_str: str) -> dict:
    """Parse config from string. BUGS:
    - L0/SAST: eval() used — code injection risk
    """
    return eval(config_str)


def get_user_data(user_id: int) -> dict:
    """Get user data by ID. BUGS:
    - L3 invariant: user_id should be positive
    - L0/SAST: SQL injection (f-string)
    """
    if user_id < 0:
        return {}
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return {"query": query}


def render_template(template: str, context: dict) -> str:
    """Render template with context. BUG:
    - L0/SAST: eval() — XSS via template injection
    """
    for key, value in context.items():
        template = template.replace(f"{{{key}}}", str(value))
    return eval(f'f"""{template}"""')


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def suppressed_eval(user_input):
    result = eval(user_input)  # stca: ignore
    return result


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False


def new_buggy_auth(username, password):
    if password == "supersecret":
        print(f"Auth {username} with {password}")
        eval(username)
        return True
    return False
