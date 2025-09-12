# Password Manager

A secure and user-friendly password manager application built with React, Node.js, Express, and SQLite.

## Features

- User registration and authentication
- Secure password storage with encryption
- Add, view, update, and delete credentials
- User profile management
- Password recovery functionality
- Two-factor authentication (2FA)

## Technologies Used

- Frontend: React, React Router, Axios
- Backend: Node.js, Express
- Database: SQLite
- Authentication: JSON Web Tokens (JWT)
- Password Hashing: bcrypt
- Encryption: CryptoJS (AES-256)

## Prerequisites

- Node.js (v14 or later)
- npm (v6 or later)

## Installation

1. Clone the repository: 

2. Install backend dependencies: 
    cd backend
    npm install

3. Install frontend dependencies:
    cd ../frontend
    npm install


4. Set up environment variables:
Create a `.env` file in the `backend` directory with the following content: 
    JWT_SECRET=your_jwt_secret_here
    ENCRYPTION_KEY=your_strong_encryption_key_here
    EMAIL_USER=[your_email@gmail.com](mailto:your_email@gmail.com)
    EMAIL_PASS=your_email_password

Replace the placeholder values with your actual secrets and credentials.

## Running the Application

1. Start the backend server:
    cd backend
    npm start
The server will run on `http://localhost:5000`.

2. Start the frontend development server:
    cd frontend
    npm start
The frontend will be available at `http://localhost:3000`.

## Usage

1. Register a new account or log in with existing credentials.
2. Use the dashboard to manage your passwords and credentials.
3. Update your profile information as needed.
4. Enable two-factor authentication for added security.

## Security Considerations

- All passwords are encrypted before being stored in the database.
- User passwords are hashed using bcrypt before storage.
- JWT is used for maintaining user sessions.
- Two-factor authentication is available for enhanced security.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.
