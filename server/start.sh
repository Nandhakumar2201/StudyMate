#!/bin/bash
# Startup script for Render deployment
# This ensures migrations run before starting the server

set -e

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput || true

echo "Starting Gunicorn..."
exec gunicorn backend.wsgi:application --bind 0.0.0.0:$PORT
