import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import hashlib
from datetime import datetime, timezone
from typing import List
import re
import bcrypt
import time

# Set page config
st.set_page_config(
    page_title="SafeTrail",
    page_icon="✈️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Embedded CSS for styling
st.markdown("""
<style>
    /* Main styles */
    .stApp {
        background-color: #f5f7fa;
    }
    
    /* Sidebar styles */
    [data-testid="stSidebar"] {
        background-color: #2c3e50;
        color: white;
    }
    
    /* Button styles */
    .stButton>button {
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: 500;
        transition: all 0.3s ease;
        border: 1px solid #3498db;
        background-color: #3498db;
        color: white;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        background-color: #2980b9;
    }
    
    /* Primary button */
    div.stButton > button:first-child {
        background-color: #2ecc71;
        border-color: #2ecc71;
    }
    
    div.stButton > button:first-child:hover {
        background-color: #27ae60;
    }
    
    /* Card styles */
    .card {
        background: white;
        border-radius: 10px;
        padding: 1.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
    }
    
    /* Success message */
    .success {
        color: #2ecc71;
    }
    
    /* Error message */
    .error {
        color: #e74c3c;
    }
    
    /* Text input */
    .stTextInput>div>div>input {
        border-radius: 8px;
        padding: 8px 12px;
    }
    
    /* Radio buttons */
    .stRadio>div {
        flex-direction: row;
        gap: 1rem;
    }
    
    /* Responsive layout */
    @media (max-width: 768px) {
        .column {
            width: 100% !important;
        }
        
        [data-testid="stSidebar"] {
            width: 100% !important;
        }
    }
</style>
""", unsafe_allow_html=True)

# Helper functions
def is_password_strong(password: str) -> bool:
    """Check if password meets complexity requirements"""
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"\d", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

def calculate_transport_fare(from_city: str, to_city: str, transport_type: str) -> int:
    """Simplified fare calculation for demo"""
    fare_rules = {
        "bus": 10,    # ₹10 per km
        "train": 5,   # ₹5 per km
        "plane": 10   # ₹10 per km
    }
    return 300 * fare_rules.get(transport_type, 10)  # Assume 300 km distance

class User:
    def __init__(self, name: str, password: str):
        if not name or not password:
            raise ValueError("Username and password are required")

        if not is_password_strong(password):
            raise ValueError("Password must be at least 8 characters with uppercase, lowercase, number and special character")

        self.name = name
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.total_spent = 0
        self.rewarded_transactions = set()
        self.last_login = datetime.now(timezone.utc)
        self.login_attempts = 0
        self.locked_until = None

    def verify_password(self, password: str) -> bool:
        """Verify the provided password against stored hash"""
        if self.locked_until and datetime.now(timezone.utc) < self.locked_until:
            raise ValueError("Account temporarily locked due to too many failed attempts")

        return bcrypt.checkpw(password.encode(), self.password_hash)

    def record_failed_attempt(self):
        """Record a failed login attempt and lock account if needed"""
        self.login_attempts += 1
        if self.login_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + datetime.timedelta(minutes=15)
            raise ValueError("Account locked for 15 minutes due to too many failed attempts")

    def reset_login_attempts(self):
        """Reset failed login attempts counter"""
        self.login_attempts = 0
        self.locked_until = None

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the user's private key"""
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def get_public_key_bytes(self) -> bytes:
        """Get the public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def update_last_login(self):
        """Update the last login timestamp"""
        self.last_login = datetime.now(timezone.utc)
        self.reset_login_attempts()

    def __repr__(self):
        return f"User(name={self.name}, total_spent={self.total_spent})"

class Transaction:
    def __init__(self, sender: str, recipient: str, amount: int, tx_type: str, metadata=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.tx_type = tx_type
        self.metadata = metadata or {}
        self.timestamp = datetime.now(timezone.utc)
        self.tx_hash = self.calculate_hash()
        self.reward_claimed = False

    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of the transaction"""
        tx_data = f"{self.sender}-{self.recipient}-{self.amount}-{self.tx_type}-{self.timestamp}"
        return hashlib.sha256(tx_data.encode()).hexdigest()

    def mark_reward_claimed(self):
        """Mark this transaction as having its reward claimed"""
        self.reward_claimed = True

    def __repr__(self):
        return f"Transaction({self.tx_type}: {self.sender} -> {self.recipient}, Amount: {self.amount})"

class Block:
    def __init__(self, previous_hash: str, transactions: List[Transaction]):
        self.timestamp = datetime.now(timezone.utc)
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of the block"""
        block_data = f"{self.timestamp}-{self.previous_hash}-{[tx.tx_hash for tx in self.transactions]}-{self.nonce}"
        return hashlib.sha256(block_data.encode()).hexdigest()

    def mine_block(self, difficulty: int = 2):
        """Mine the block with proof-of-work"""
        while not self.hash.startswith('0' * difficulty):
            self.nonce += 1
            self.hash = self.calculate_hash()

    def __repr__(self):
        return f"Block(Hash: {self.hash[:10]}..., Transactions: {len(self.transactions)})"

class Blockchain:
    def __init__(self):
        self.difficulty = 2
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.users = {}
        self.reviews = []
        self.bookings = []
        self.balances = {}

    def create_genesis_block(self) -> Block:
        """Create the first block in the blockchain"""
        genesis = Block("0", [])
        genesis.mine_block(difficulty=self.difficulty)
        return genesis

    def add_user(self, user: User):
        """Add a new user to the system"""
        if user.name in self.users:
            raise ValueError("Username already exists")
        self.users[user.name] = user
        self.balances[user.name] = 1000  # Starting balance

    def authenticate_user(self, username: str, password: str) -> User | None:
        """Authenticate a user with username and password"""
        user = self.users.get(username)
        if not user:
            return None

        try:
            if user.verify_password(password):
                user.update_last_login()
                return user
        except ValueError as e:
            user.record_failed_attempt()
            raise e

        user.record_failed_attempt()
        return None

    def add_transaction(self, transaction: Transaction) -> bool:
        """Add a new transaction to the pending transactions"""
        if transaction.sender != "System":
            if self.balances.get(transaction.sender, 0) < transaction.amount:
                print("Insufficient balance for transaction.")
                return False
            self.balances[transaction.sender] -= transaction.amount

        self.balances[transaction.recipient] = self.balances.get(transaction.recipient, 0) + transaction.amount
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self) -> tuple[Block | None, str]:
        """Mine all pending transactions into a new block"""
        if not self.pending_transactions:
            return None, "No transactions to mine."

        new_block = Block(self.chain[-1].hash, self.pending_transactions)
        new_block.mine_block(difficulty=self.difficulty)
        self.chain.append(new_block)
        mined_transactions = self.pending_transactions.copy()
        self.pending_transactions = []
        return new_block, mined_transactions

    def check_transport_fare(self, from_city: str, to_city: str, transport_type: str) -> int:
        """Check the transport fare without booking"""
        return calculate_transport_fare(from_city, to_city, transport_type)

    def book_transport_ticket(self, user: User, from_city: str, to_city: str, transport_type: str) -> tuple[bool, str]:
        """Book a transport ticket with dynamic fare calculation"""
        fare = calculate_transport_fare(from_city, to_city, transport_type)

        if self.balances.get(user.name, 0) < fare:
            return False, f"Insufficient funds. Fare: {fare} coins, Your balance: {self.balances.get(user.name, 0)} coins"

        booking = {
            "user": user.name,
            "from": from_city,
            "to": to_city,
            "fare": fare,
            "transport_type": transport_type,
            "timestamp": str(datetime.now(timezone.utc))
        }
        self.bookings.append(booking)

        tx = Transaction(user.name, "TransportOperator", fare, "transport_booking", booking)
        if self.add_transaction(tx):
            user.total_spent += fare
            return True, (
                f"🎟️ {transport_type.capitalize()} ticket booked!\n"
                f"From: {from_city}\n"
                f"To: {to_city}\n"
                f"Fare: {fare} coins\n"
                f"Total spent: {user.total_spent} coins\n"
                f"Transaction ID: {tx.tx_hash[:8]}"
            )
        return False, f"Failed to book {transport_type} ticket."

    def add_coins(self, user: User, amount: int) -> tuple[bool, str]:
        """Add coins to user's balance"""
        if amount <= 0:
            return False, "Amount must be positive"

        tx = Transaction(
            "System",
            user.name,
            amount,
            "deposit",
            {"reason": "Added coins to balance"}
        )
        if self.add_transaction(tx):
            return True, f"Added {amount} coins to your balance. New balance: {self.balances.get(user.name, 0)} coins"
        return False, "Failed to add coins"

    def leave_review(self, user: User, destination: str, rating: int, comment: str) -> tuple[bool, str]:
        """Add a review for a destination"""
        review = {
            "user": user.name,
            "destination": destination,
            "rating": rating,
            "comment": comment,
            "timestamp": str(datetime.now(timezone.utc))
        }
        self.reviews.append(review)

        tx = Transaction(user.name, "System", 0, "review", review)
        self.add_transaction(tx)
        return True, "Review submitted successfully."

    def get_user_transactions(self, username: str) -> List[Transaction]:
        """Get all transactions for a user"""
        transactions = []
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == username or tx.recipient == username:
                    transactions.append(tx)
        return transactions + [
            tx for tx in self.pending_transactions
            if tx.sender == username or tx.recipient == username
        ]

    def calculate_loyalty_reward(self, user: User) -> int:
        """Calculate reward based on unrewarded transport booking transactions"""
        unrewarded_txs = [
            tx for tx in self.get_user_transactions(user.name)
            if tx.tx_type == "transport_booking" and not tx.reward_claimed
        ]
        if not unrewarded_txs:
            return 0
        # 2% of total unrewarded spending with minimum 10 coins
        total_unrewarded = sum(tx.amount for tx in unrewarded_txs)
        return max(int(total_unrewarded * 0.02), 10)

    def reward_loyalty(self, user: User) -> tuple[bool, int, str]:
        """Claim loyalty reward for unrewarded transactions"""
        unrewarded_txs = [
            tx for tx in self.get_user_transactions(user.name)
            if tx.tx_type == "transport_booking" and not tx.reward_claimed
        ]

        if not unrewarded_txs:
            return False, 0, "No eligible transactions for reward"

        reward_amount = self.calculate_loyalty_reward(user)

        # Mark transactions as rewarded
        for tx in unrewarded_txs:
            tx.mark_reward_claimed()
            if tx.tx_hash not in user.rewarded_transactions:
                user.rewarded_transactions.add(tx.tx_hash)

        tx = Transaction(
            "System",
            user.name,
            reward_amount,
            "reward",
            {"reason": "Loyalty", "transactions": [tx.tx_hash for tx in unrewarded_txs]}
        )
        if self.add_transaction(tx):
            return True, reward_amount, f"Rewarded for {len(unrewarded_txs)} ticket(s)"
        return False, 0, "Failed to claim loyalty reward"

    def __repr__(self):
        return f"Blockchain(Blocks: {len(self.chain)}, Users: {len(self.users)})"

class TravelBlockchainApp:
    def __init__(self):
        self.blockchain = Blockchain()
        self.current_user = None

    def register_user(self, name: str, password: str, confirm_password: str) -> str:
        """Register a new user with password authentication"""
        if password != confirm_password:
            return "Passwords do not match"

        try:
            user = User(name, password)
            self.blockchain.add_user(user)
            self.current_user = user
            return f"User {name} registered successfully with 1000 coins."
        except ValueError as e:
            return str(e)

    def login_user(self, name: str, password: str) -> str:
        """Authenticate and login a user"""
        try:
            user = self.blockchain.authenticate_user(name, password)
            if user:
                self.current_user = user
                return f"Welcome back, {name}! Total spent: {self.current_user.total_spent} coins"
            return "Invalid username or password"
        except ValueError as e:
            return str(e)

    def check_transport_fare(self, from_city: str, to_city: str, transport_type: str) -> str:
        if not self.current_user:
            return "Please login first."
        fare = self.blockchain.check_transport_fare(from_city, to_city, transport_type)
        return f"Estimated {transport_type} fare from {from_city} to {to_city}: {fare} coins"

    def book_transport_ticket(self, from_city: str, to_city: str, transport_type: str) -> str:
        if not self.current_user:
            return "Please login first."
        success, message = self.blockchain.book_transport_ticket(
            self.current_user, from_city, to_city, transport_type
        )
        return message

    def add_coins(self, amount: str) -> str:
        if not self.current_user:
            return "Please login first."
        try:
            amount = int(amount)
            if amount <= 0:
                return "Amount must be positive"
        except ValueError:
            return "Please enter a valid number"
        success, message = self.blockchain.add_coins(self.current_user, amount)
        return message

    def leave_review(self, destination: str, rating: str, comment: str) -> str:
        if not self.current_user:
            return "Please login first."
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                return "Rating must be between 1 and 5."
        except ValueError:
            return "Rating must be a number."
        success, message = self.blockchain.leave_review(self.current_user, destination, rating, comment)
        return message

    def view_reviews(self) -> str:
        reviews = self.blockchain.reviews
        if not reviews:
            return "No reviews yet."
        return "\n".join([
            f"{r['user']} rated {r['destination']} {r['rating']}/5: {r['comment']}"
            for r in reviews
        ])

    def view_balance(self) -> str:
        if not self.current_user:
            return "Please login first."
        balance = self.blockchain.balances.get(self.current_user.name, 0)
        reward = self.blockchain.calculate_loyalty_reward(self.current_user)
        return (
            f"Your current balance: {balance} coins\n"
            f"Total spent: {self.current_user.total_spent} coins\n"
            f"Available loyalty reward: {reward} coins\n"
            f"Eligible tickets: {len([tx for tx in self.blockchain.get_user_transactions(self.current_user.name) if tx.tx_type == 'transport_booking' and not tx.reward_claimed])}"
        )

    def mine_transactions(self) -> str:
        if not self.current_user:
            return "Please login first."
        new_block, mined_transactions = self.blockchain.mine_pending_transactions()
        if not new_block:
            return "No transactions to mine."
        tx_details = "\n".join([
            f"• {tx.sender} → {tx.recipient}: {tx.amount} coins ({tx.tx_type})"
            for tx in mined_transactions
        ])
        return (
            "⛏️ Mining complete! New block added to blockchain:\n\n"
            f"Block #{len(self.blockchain.chain)-1}\n"
            f"Hash: {new_block.hash[:16]}...\n"
            f"Previous Hash: {new_block.previous_hash[:16]}...\n"
            f"Timestamp: {new_block.timestamp}\n"
            f"Nonce: {new_block.nonce}\n\n"
            "Transactions included:\n"
            f"{tx_details}"
        )

    def reward_loyalty(self) -> str:
        if not self.current_user:
            return "Please login first."
        success, reward_amount, details = self.blockchain.reward_loyalty(self.current_user)
        if success:
            return (
                "🎉 Loyalty Reward Claimed!\n\n"
                f"Amount: {reward_amount} coins\n"
                f"Details: {details}\n\n"
                f"Your new balance: {self.blockchain.balances.get(self.current_user.name, 0)} coins"
            )
        return "Failed to claim loyalty reward. " + details

# Initialize the app
if 'app' not in st.session_state:
    st.session_state.app = TravelBlockchainApp()

# Helper function for displaying user info
def show_user_info():
    if st.session_state.app.current_user:
        user = st.session_state.app.current_user
        st.sidebar.success(f"Logged in as: {user.name}")
        
        with st.sidebar.expander("Account Info", expanded=True):
            balance = st.session_state.app.blockchain.balances.get(user.name, 0)
            st.metric("Balance", f"{balance} coins")
            
            reward = st.session_state.app.blockchain.calculate_loyalty_reward(user)
            st.metric("Available Reward", f"{reward} coins")
            
            if st.button("Logout"):
                st.session_state.app.current_user = None
                st.experimental_rerun()

# Header with logo
def header():
    col1, col2 = st.columns([1, 3])
    with col1:
        st.image("https://via.placeholder.com/100x100?text=SafeTrail", width=100)
    with col2:
        st.title("SafeTrail")
        st.markdown("Your blockchain-powered travel companion ✈️")

# Main app layout
header()

# Sidebar for user auth
with st.sidebar:
    st.header("Account")
    
    if not st.session_state.app.current_user:
        auth_tab = st.radio("Auth", ["Login", "Register"])
        
        if auth_tab == "Login":
            with st.form("login_form"):
                login_name = st.text_input("Username")
                login_pass = st.text_input("Password", type="password")
                if st.form_submit_button("Login"):
                    with st.spinner("Authenticating..."):
                        try:
                            result = st.session_state.app.login_user(login_name, login_pass)
                            st.success(result)
                            time.sleep(1)
                            st.experimental_rerun()
                        except Exception as e:
                            st.error(str(e))
        
        elif auth_tab == "Register":
            with st.form("register_form"):
                reg_name = st.text_input("Username")
                reg_pass = st.text_input("Password", type="password")
                reg_pass_confirm = st.text_input("Confirm Password", type="password")
                
                st.markdown("**Password Requirements:**")
                st.markdown("- 8+ characters")
                st.markdown("- Uppercase letter")
                st.markdown("- Lowercase letter")
                st.markdown("- Number")
                st.markdown("- Special character")
                
                if st.form_submit_button("Register"):
                    if reg_pass != reg_pass_confirm:
                        st.error("Passwords don't match!")
                    else:
                        with st.spinner("Creating account..."):
                            try:
                                result = st.session_state.app.register_user(reg_name, reg_pass, reg_pass_confirm)
                                st.success(result)
                                time.sleep(1)
                                st.experimental_rerun()
                            except Exception as e:
                                st.error(str(e))
    
    show_user_info()

# Main content
if st.session_state.app.current_user:
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "🏡 Home", 
        "🎟️ Book Tickets", 
        "💰 Add Coins",
        "🗺️ Travel Planner",
        "✍️ Reviews", 
        "⛏️ Blockchain", 
        "🎁 Rewards"
    ])
    
    with tab1:
        st.header("Welcome to SafeTrail!")
        st.markdown("""
        ### Your Travel Companion on the Blockchain
            
        **Features:**
        - Book bus, train, and plane tickets
        - Earn loyalty rewards for your travels
        - Leave reviews and share experiences
        - Secure blockchain transactions
        """)
        
        st.image("https://images.unsplash.com/photo-1500835556837-99ac94a94552?w=800", 
                caption="Start your journey with SafeTrail!")
        
        with st.expander("Quick Actions"):
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("Check Balance"):
                    st.info(st.session_state.app.view_balance())
            with col2:
                if st.button("View Recent Transactions"):
                    st.info("Feature coming soon!")
            with col3:
                if st.button("Claim Rewards"):
                    result = st.session_state.app.reward_loyalty()
                    st.success(result)
    
    with tab2:
        st.header("Book Transportation")
        
        col1, col2 = st.columns(2)
        
        with col1:
            with st.form("booking_form"):
                transport_type = st.radio(
                    "Transport Type",
                    ["bus", "train", "plane"],
                    horizontal=True
                )
                
                from_city = st.text_input("From City")
                to_city = st.text_input("To City")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.form_submit_button("Check Fare"):
                        fare = st.session_state.app.check_transport_fare(from_city, to_city, transport_type)
                        st.info(fare)
                with col2:
                    if st.form_submit_button("Book Ticket"):
                        result = st.session_state.app.book_transport_ticket(from_city, to_city, transport_type)
                        st.success(result)
        
        with col2:
            st.markdown("### Recent Bookings")
            bookings = st.session_state.app.blockchain.bookings[-5:][::-1]
            if not bookings:
                st.info("No bookings yet")
            else:
                for book in bookings:
                    with st.expander(f"{book['transport_type'].capitalize()} to {book['to']}"):
                        st.markdown(f"""
                        **From**: {book['from']}  
                        **To**: {book['to']}  
                        **Fare**: {book['fare']} coins  
                        **Date**: {book['timestamp']}
                        """)
    
    with tab3:
        st.header("Add Coins to Your Account")
        
        with st.form("add_coins_form"):
            amount = st.number_input(
                "Amount to Add", 
                min_value=1, 
                max_value=10000,
                step=100,
                value=500
            )
            
            if st.form_submit_button("Add Coins"):
                result = st.session_state.app.add_coins(str(amount))
                if "Added" in result:
                    st.success(result)
                    st.balloons()
                else:
                    st.error(result)
        
        st.markdown("### Recent Deposits")
        deposits = [
            tx for tx in st.session_state.app.blockchain.get_user_transactions(
                st.session_state.app.current_user.name
            ) if tx.tx_type == "deposit"
        ][-3:][::-1]
        
        if not deposits:
            st.info("No coin deposits yet")
        else:
            for dep in deposits:
                st.markdown(f"""
                **{dep.amount} coins** added  
                *{dep.timestamp.strftime('%Y-%m-%d %H:%M')}*
                """)
                st.divider()
    
    with tab4:
        st.header("Travel Itinerary Planner")
        
        with st.form("planner_form"):
            col1, col2 = st.columns(2)
            with col1:
                city = st.text_input("City to Visit")
            with col2:
                interests = st.text_input("Your Interests (comma separated)", 
                                        placeholder="e.g., museums, hiking, food")
            
            if st.form_submit_button("Generate Itinerary"):
                if city and interests:
                    with st.spinner("Creating your perfect itinerary..."):
                        # This is a placeholder - implement your actual LLM call here
                        itinerary = f"""
                        **Suggested Itinerary for {city}**:
                        
                        - Morning: Visit local museums
                        - Afternoon: {interests.split(',')[0]} exploration
                        - Evening: Dinner at top-rated local restaurant
                        """
                        st.markdown(itinerary)
                        st.success("Enjoy your trip!")
                else:
                    st.warning("Please enter both city and interests")
        
        st.markdown("### Sample Itineraries")
        st.markdown("""
        - **Mumbai**: Gateway of India → Marine Drive → Street Food Tour
        - **Delhi**: Red Fort → Chandni Chowk → India Gate
        - **Goa**: Beach Hopping → Water Sports → Night Markets
        """)
    
    with tab5:
        st.header("Travel Reviews")
        
        with st.expander("Leave a Review", expanded=True):
            with st.form("review_form"):
                dest = st.text_input("Destination")
                rating = st.slider("Rating", 1, 5, 3)
                comment = st.text_area("Your Review")
                if st.form_submit_button("Submit Review"):
                    result = st.session_state.app.leave_review(dest, str(rating), comment)
                    st.success(result)
        
        st.markdown("### Recent Reviews")
        reviews = st.session_state.app.blockchain.reviews[-5:][::-1]
        if not reviews:
            st.info("No reviews yet")
        else:
            for rev in reviews:
                with st.container():
                    st.markdown(f"""
                    **{rev['user']}** rated **{rev['destination']}** {rev['rating']}/5:
                    > {rev['comment']}
                    """)
                    st.markdown(f"*{rev['timestamp']}*")
                    st.divider()
    
    with tab6:
        st.header("Blockchain Explorer")
        
        if st.button("⛏️ Mine Transactions", type="primary"):
            with st.spinner("Mining block..."):
                result = st.session_state.app.mine_transactions()
                st.success(result)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Blockchain Info")
            st.metric("Chain Length", f"{len(st.session_state.app.blockchain.chain)} blocks")
            st.metric("Pending Transactions", len(st.session_state.app.blockchain.pending_transactions))
        
        with col2:
            st.markdown("### Latest Block")
            if st.session_state.app.blockchain.chain:
                latest = st.session_state.app.blockchain.chain[-1]
                st.json({
                    "index": len(st.session_state.app.blockchain.chain)-1,
                    "hash": latest.hash[:16] + "...",
                    "previous_hash": latest.previous_hash[:16] + "...",
                    "timestamp": str(latest.timestamp),
                    "transactions": len(latest.transactions),
                    "nonce": latest.nonce
                })
    
    with tab7:
        st.header("Loyalty Rewards")
        
        reward = st.session_state.app.blockchain.calculate_loyalty_reward(
            st.session_state.app.current_user
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Available Reward", f"{reward} coins")
            
            if st.button("🎁 Claim Reward", type="primary"):
                success, amount, details = st.session_state.app.blockchain.reward_loyalty(
                    st.session_state.app.current_user
                )
                if success:
                    st.balloons()
                    st.success(f"Success! Claimed {amount} coins as reward.")
                else:
                    st.warning(details)
        
        with col2:
            st.markdown("### Reward Details")
            st.markdown("""
            - Earn 2% of your ticket purchases as rewards
            - Minimum reward is 10 coins
            - Each ticket can only be rewarded once
            """)

else:
    st.warning("Please login or register to access the travel platform")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Why Choose SafeTrail?
        
        - Secure blockchain transactions
        - Competitive ticket prices
        - Earn rewards for your travels
        - Share your experiences
        """)
    
    with col2:
        st.image("https://images.unsplash.com/photo-1503220317375-aaad61436b1b?w=800", 
                 caption="Your next adventure awaits!")