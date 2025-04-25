# BioCipher

A secure file encryption and management system built with Flask.

## Features

- User authentication and authorization
- File encryption and decryption
- Admin dashboard for user management
- Secure file storage
- reCAPTCHA integration

## Setup

1. Clone the repository:
```bash
git clone https://github.com/kunal-masurkar/biocipher.git
cd biocipher
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# Create a .env file with the following variables:
SECRET_KEY=your_secret_key
ENCRYPTION_KEY=your_encryption_key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
```

5. Initialize the database:
```bash
flask db upgrade
```

6. Run the application:
```bash
python app.py
```

## Deployment

This application is configured for deployment on Render. The `render.yaml` file contains all necessary configuration.

## Security

- All files are encrypted before storage
- Passwords are hashed using Werkzeug
- Admin access is protected
- reCAPTCHA integration for login/registration

## License

Apache2.0 License 
