# JWT Authentication Example

This project demonstrates how to implement JWT (JSON Web Token) authentication in an ASP.NET Core application. It includes examples of using both a **secret key** and **private/public key pair** for token signing and validation.

## Key Features

- **JWT Authentication**: Includes both secret key and RSA private/public key signing methods for token validation.
- **SQLite Database**: The project uses SQLite as the database for storing user data.
- **ASP.NET Core**: The application is built using ASP.NET Core with JWT-based authorization and role management.

## Project Branches

- **`feature/secretKey`**: Implements JWT authentication using a secret key for signing and validation.
  - [Link to branch](https://github.com/ZuraArabidze/JwtAuth/tree/feature/secretKey)

- **`feature/private-public_Keys`**: Implements JWT authentication using a private/public RSA key pair for signing and validation.
  - [Link to branch](https://github.com/ZuraArabidze/JwtAuth/tree/feature/private-public_Keys)

## How to Run

1. Clone the repository:

   ```bash
   git clone https://github.com/ZuraArabidze/JwtAuth.git
   cd JwtAuth
