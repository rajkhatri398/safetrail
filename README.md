# SafeTrail ✈️

A blockchain-secured travel booking platform with an integrated AI itinerary planner, built in Python with Streamlit.

SafeTrail lets users register, book multi-modal transport tickets, earn loyalty rewards, leave reviews, and generate AI-powered day-trip itineraries — with every transaction recorded on a custom Proof-of-Work blockchain.

## Features

- **Blockchain-backed transactions** — every booking, deposit, and reward is recorded as a transaction and mined into a block using a custom Proof-of-Work blockchain (SHA-256 hashing).
- **Secure authentication** — passwords are hashed with `bcrypt`, each user gets an RSA-2048 keypair for signing, and accounts lock temporarily after repeated failed login attempts.
- **Multi-modal transport booking** — book bus, train, or plane tickets with dynamic fare calculation.
- **Digital wallet & loyalty rewards** — track balances, earn 2% of ticket spend back as rewards.
- **AI itinerary planner** — generate a personalized day-trip itinerary from a city and a list of interests, powered by a [LangGraph](https://github.com/langchain-ai/langgraph) workflow calling a Groq-hosted LLM (Llama 3.3 70B).
- **Reviews** — leave and browse destination reviews.
- **Blockchain explorer** — inspect the chain, mine pending transactions, and view block details.

## Tech Stack

| Layer | Technology |
|---|---|
| UI | Streamlit |
| Security | `cryptography` (RSA-2048), `bcrypt` |
| Blockchain | Custom Python implementation (SHA-256, Proof-of-Work) |
| AI / LLM | LangChain, LangGraph, Groq (Llama 3.3 70B) |
| Language | Python 3 |

## Getting Started

### Prerequisites

- Python 3.10+
- A free [Groq API key](https://console.groq.com/) (only needed for the AI itinerary planner)

### Installation

```bash
git clone https://github.com/rajkhatri398/safetrail.git
cd safetrail
pip install -r requirements.txt
```

### Configuring the AI Itinerary Planner

The itinerary planner needs a Groq API key. It is **never hardcoded** — set it one of two ways:

**Option A — Streamlit secrets (recommended):**

Create `.streamlit/secrets.toml` in the project root:

```toml
GROQ_API_KEY = "your-groq-api-key-here"
```

**Option B — Environment variable:**

```bash
export GROQ_API_KEY="your-groq-api-key-here"   # macOS/Linux
setx GROQ_API_KEY "your-groq-api-key-here"      # Windows
```

If no key is configured, every other feature still works — the planner tab will just show a friendly warning instead of an itinerary.

### Running the app

```bash
streamlit run safetrail.py
```

Then open the local URL Streamlit prints (typically `http://localhost:8501`).

## How the AI Itinerary Planner Works

The planner runs as a small LangGraph state machine:

1. **`validate_input`** — checks that a city and at least one interest were provided, and cleans up the interest list.
2. **`generate_itinerary`** — calls a Groq-hosted LLM (`llama-3.3-70b-versatile`) with a prompt template to generate a brief, bulleted day-trip itinerary.

```
validate_input → generate_itinerary → END
```

This keeps input validation and generation as separate, testable steps rather than one large function.

## Project Structure

```
safetrail/
├── safetrail.py        # Main Streamlit app (auth, blockchain, booking, AI planner, reviews)
├── requirements.txt    # Python dependencies
└── README.md
```

## Security Notes

- Passwords are never stored in plaintext — only `bcrypt` hashes.
- API keys are read from `st.secrets` or environment variables only — **do not commit real keys to source control**.
- The blockchain implementation here is for learning/demonstration purposes (a simulated single-process chain), not a production-grade distributed ledger.

## Roadmap / Ideas

- Persist blockchain state to disk or a database (currently in-memory, resets on restart)
- Add real-time fare data instead of the simplified distance-based calculation
- Expand the itinerary planner to multi-day trips

## License

Add your preferred license here (e.g., MIT).
