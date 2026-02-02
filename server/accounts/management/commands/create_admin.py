"""
Management command to create admin user if it doesn't exist.
This is useful for deployment environments where you can't use createsuperuser interactively.
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import os

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates an admin user if it does not exist'

    def add_arguments(self, parser):
        parser.add_argument(
            '--username',
            type=str,
            default='Admin',
            help='Username for admin user (default: Admin)'
        )
        parser.add_argument(
            '--email',
            type=str,
            default='jacsiceadmin@gmail.com',
            help='Email for admin user (default: jacsiceadmin@gmail.com)'
        )
        parser.add_argument(
            '--password',
            type=str,
            default=None,
            help='Password for admin user (default: from ADMIN_PASSWORD env var or jacsice@Admin)'
        )

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        password = options['password'] or os.environ.get('ADMIN_PASSWORD', 'jacsice@Admin')

        # Check if admin user already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'Admin user "{username}" already exists. Skipping creation.')
            )
            return

        # Check if email is already taken
        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.ERROR(f'Email "{email}" is already in use by another user.')
            )
            return

        # Create admin user
        try:
            admin_user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role='admin',
                is_staff=True,
                is_superuser=True,
                is_active=True
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created admin user: {username} ({email})'
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating admin user: {str(e)}')
            )
