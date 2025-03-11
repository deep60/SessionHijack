# SessionHijack

A high-performance session hijacking detection and prevention system implemented in Rust. This tool leverages Rust's memory safety and zero-cost abstractions to provide real-time monitoring and protection against various session hijacking attacks.

## Features

- **Multi-Factor Session Validation**:
  - IP address binding
  - User agent verification
  - Device fingerprinting
  - CSRF token protection
  - Session timeout handling

- **Protection Against**:
  - Session fixation
  - Cookie theft
  - MITM attacks
  - XSS-based session hijacking

- **Technical Implementation**:
  - Tokio-based async runtime
  - Comprehensive session storage with PostgreSQL
  - Secure authentication with Argon2 password hashing
  - Demo frontend for attack simulations

## Prerequisites

- Rust 1.75.0 or higher
- Cargo package manager
- PostgreSQL 14+ (for session storage)
- Web browser for frontend demo

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/SessionHijack.git
   cd SessionHijack
   ```

2. **Set up the database**:
   ```bash
   # Create PostgreSQL database
   createdb session_hijack
   
   # Set environment variable
   export DATABASE_URL=postgres://username:password@localhost/session_hijack
   
   # Apply database migrations
   psql -d session_hijack -f migrations/db.sql
   ```

3. **Build the project**:
   ```bash
   cargo build --release
   ```

## Running the Application

1. **Start the backend server**:
   ```bash
   cargo run --release
   ```
   The server will start on http://localhost:8080

2. **Access the frontend demo**:
   - Open your web browser and navigate to `http://localhost:8080`
   - Default login credentials: 
     - Username: `user`
     - Password: `password`

## Demo Features

The demo application includes a frontend interface that demonstrates session hijacking protection:

- **Login/Logout**: Basic authentication flow
- **Session Management**: Shows active sessions and their details
- **Attack Simulations**:
  - Simulate IP address change (detects potential session hijacking)
  - Simulate user agent change (detects browser fingerprint violations)
  - Test CSRF protection

## Project Structure

```
SessionHijack/
├── Cargo.toml              # Rust dependencies
├── migrations/             # Database setup
│   └── db.sql              # SQL schema
├── src/                    # Backend code
│   ├── main.rs             # Application entry point
│   ├── routes/             # API endpoints
│   │   └── auth.rs         # Authentication routes
│   ├── services/           # Core business logic
│   │   ├── auth_service.rs # Authentication service
│   │   ├── session_protection.rs # Security features
│   │   └── session_services.rs   # Session management
│   ├── models/             # Data models
│   ├── error.rs            # Error handling
│   └── config.rs           # Application configuration
└── frontend/              # Demo UI
    └── src/
        ├── css/           # Styles
        ├── js/            # Frontend logic
        └── *.html         # UI pages
```

## Key Components

### Main Application (main.rs)

The `main.rs` file is the entry point for the application. It:

1. Sets up the Actix Web server
2. Initializes the database connection pool
3. Creates the authentication and session services
4. Registers HTTP routes for both the API and static files
5. Configures security settings
6. Starts the web server

### Session Protection (session_protection.rs)

This module provides the core security features for preventing session hijacking:

- Session validation logic
- IP address verification
- User agent verification
- Session expiration handling

### Authentication Service (auth_service.rs)

Handles user authentication using secure password hashing with Argon2.

### Session Service (session_services.rs)

Manages user sessions, including:
- Creating new sessions
- Validating existing sessions
- Generating security tokens
- Device fingerprinting

## Security Measures

### IP Address Binding
Sessions are bound to the IP address they were created from. Any change in IP address will invalidate the session, protecting against session hijacking attempts from different network locations.

### User Agent Verification
The user's browser signature is captured and verified on each request. Changes in the user agent string might indicate a session hijacking attempt.

### Secure Cookie Configuration
Cookies used for session management are configured with:
- HttpOnly flag: Prevents JavaScript access to the cookie
- Secure flag: Ensures cookies are only sent over HTTPS
- SameSite=Strict: Mitigates CSRF attacks

### Session Timeout
Automatic expiration after a period of inactivity (default: 1 hour) reduces the window of opportunity for session hijacking.

### CSRF Protection
Cross-Site Request Forgery protection through unique tokens ensures that requests to the server come from legitimate sources.

### Device Fingerprinting
Advanced device fingerprinting combines multiple browser characteristics to create a unique signature, adding an extra layer of authentication.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
