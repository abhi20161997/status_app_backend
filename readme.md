# Open Status Application

## Overview

The Open Status Application is a Django-based web application designed to help organizations manage and communicate the status of their services, incidents, and maintenance activities. It provides a robust API for managing organizations, teams, services, incidents, and maintenance schedules, as well as a public status page for external stakeholders.

## Features

1. **User Authentication**
   - User signup and login
   - JWT-based authentication
   - Token verification

2. **Organization Management**
   - Create and manage organizations
   - Invite members to organizations
   - Accept invitations to join organizations

3. **Team Management**
   - Create teams within organizations
   - Add/remove members from teams
   - Assign services to teams

4. **Service Management**
   - Create and manage services
   - Update service status
   - Assign services to teams

5. **Incident Management**
   - Create and track incidents
   - Add updates to incidents
   - Associate incidents with services

6. **Maintenance Management**
   - Schedule and manage maintenance activities
   - Associate maintenance with services

7. **Public Status Page**
   - Display public status information for each organization
   - Show active incidents and upcoming maintenance

8. **Real-time Updates**
   - WebSocket integration for real-time status updates

9. **External Status API**
   - Provide a public API for external status checks

## Setup Instructions

### Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)
- PostgreSQL (recommended for production)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/abhi20161997/status_app_backend.git
   cd status_app_backend
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run migrations:
   ```
   python manage.py migrate
   ```

5. Create a superuser:
   ```
   python manage.py createsuperuser
   ```

6. Run the development server:
   ```
   python manage.py runserver
   ```

### Running with Daphne (for WebSocket support)

To run the application with Daphne for WebSocket support:

```
daphne -b 0.0.0.0 -p 8000 PlivoAssignment.asgi:application
```

## API Endpoints

- `https://documenter.getpostman.com/view/25615441/2sAXxTcAeK`: Postman Collection Documentation

## WebSocket

The application uses WebSockets for real-time updates. The WebSocket URL format is:

```
ws://<domain>/ws/status/<organization_id>/
```
