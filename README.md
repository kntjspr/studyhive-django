# StudyHive Backend (Django)

This is a Django port of the original Node.js/Express backend for StudyHive.

## Features

- User authentication with email OTP verification
- JWT token-based session management
- PostgreSQL database integration
- Resend API for email delivery
- RESTful API for frontend integration

## Requirements

- Python 3.9+
- PostgreSQL 12+
- Resend API account for email delivery

## Setup

1. Clone the repository
2. Set up a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure your environment variables in the `.env` file:
   - Generate a secure `SECRET_KEY` for Django
   - Set your PostgreSQL database credentials
   - Add your Resend API key and email settings

5. Run database migrations:

```bash
python manage.py migrate
```

6. Create a superuser (admin):

```bash
python manage.py createsuperuser
```

7. Run the development server:

```bash
python manage.py runserver
```

## API Endpoints

Refer to postman_collection.json for the API endpoints.

## Development

To run the server in debug mode:

```bash
python manage.py runserver
```

To run tests:

```bash
python manage.py test
```

## Deployment

For production deployment:

1. Set `DEBUG=False` in `.env`
2. Configure proper `ALLOWED_HOSTS` and `CORS_ALLOWED_ORIGINS`
3. Use a production-ready server like Gunicorn or uWSGI
4. Set up a proper PostgreSQL database (not SQLite)
5. Configure appropriate security settings for production

Example with Gunicorn:

```bash
gunicorn studyhive.wsgi:application
```
