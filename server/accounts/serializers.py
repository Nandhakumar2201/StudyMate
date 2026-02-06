from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.exceptions import AuthenticationFailed

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'first_name', 'last_name']
        read_only_fields = ['id']

def get_static_admin_user():
    """If static admin credentials are set, get or create the admin user (so JWT works)."""
    username = getattr(settings, 'STATIC_ADMIN_USERNAME', None)
    password = getattr(settings, 'STATIC_ADMIN_PASSWORD', None)
    email = getattr(settings, 'STATIC_ADMIN_EMAIL', None)
    if not username or not password:
        return None
    user, _ = User.objects.get_or_create(
        username=username,
        defaults={
            'email': email or f'{username}@localhost',
            'role': 'admin',
            'is_staff': True,
            'is_superuser': True,
            'is_active': True,
        },
    )
    if not user.check_password(password):
        user.set_password(password)
        user.save(update_fields=['password'])
    return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'username'
    
    def validate(self, attrs):
        username_or_email = attrs.get('username')
        password = attrs.get('password')
        
        # 1) Static admin: if credentials match static admin, use that (create in DB if needed)
        static_username = getattr(settings, 'STATIC_ADMIN_USERNAME', None)
        static_password = getattr(settings, 'STATIC_ADMIN_PASSWORD', None)
        static_email = getattr(settings, 'STATIC_ADMIN_EMAIL', None)
        if static_username and static_password:
            if username_or_email in (static_username, static_email) and password == static_password:
                user = get_static_admin_user()
                if user:
                    refresh = self.get_token(user)
                    return {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'role': user.role,
                        'username': user.username,
                    }
        
        # 2) Normal: find by username or email and authenticate
        user_obj = None
        try:
            user_obj = User.objects.get(username=username_or_email)
        except User.DoesNotExist:
            try:
                user_obj = User.objects.get(email=username_or_email)
            except User.DoesNotExist:
                pass
        
        if user_obj:
            user = authenticate(username=user_obj.username, password=password)
        else:
            user = None
        
        if not user:
            raise AuthenticationFailed('Invalid credentials')
        
        refresh = self.get_token(user)
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'role': user.role,
            'username': user.username,
        }
        return data

