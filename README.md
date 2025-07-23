# SafeTrail - Blockchain-Powered Travel Platform ✈️🔗

![SafeTrail Banner](https://via.placeholder.com/1200x400?text=SafeTrail+Blockchain+Travel+Platform)

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Future Roadmap](#future-roadmap)
- [Contributing](#contributing)
- [License](#license)

## Overview

SafeTrail is an innovative travel platform that leverages blockchain technology to provide secure, transparent, and rewarding travel experiences. The application combines transportation booking with blockchain security features, creating a decentralized ecosystem for travelers.

## Key Features

### 🔐 Secure Authentication System
- RSA-2048 public/private key encryption
- Bcrypt password hashing
- Account lockout after 5 failed attempts
- Session management

### 🚍 Multi-Modal Transportation
- Book bus, train, and plane tickets
- Dynamic fare calculation
- Booking history stored on blockchain
- Real-time balance updates

### 💰 Digital Wallet & Rewards
- Starting balance of 1000 coins
- 2% loyalty rewards on bookings
- Minimum 10 coin reward guarantee
- Transparent reward tracking

### ⛓️ Blockchain Core
- Proof-of-Work consensus (2 difficulty)
- SHA-256 hashing algorithm
- Transaction verification system
- Public ledger explorer

### ✨ Additional Features
- Destination reviews with ratings
- Travel itinerary planner
- Transaction history viewer
- Responsive UI with dark/light mode

## Technology Stack

### Backend
- Python 3.9+
- `cryptography` library (RSA, SHA-256)
- `bcrypt` for password hashing
- `streamlit` web framework

### Security
- Asymmetric encryption for all transactions
- Password complexity enforcement
- Digital signatures
- Timestamp validation

### Data Structures
- Custom blockchain implementation
- Transaction and block classes
- User management system

## Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/safetrail.git
   cd safetrail
