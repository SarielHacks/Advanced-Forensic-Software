import jwt
import datetime
import hashlib
import uuid
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

class SecurityManager:
    def __init__(self, jwt_secret='your-secret-key'):
        self.jwt_secret = jwt_secret
        self.sessions = {}
        self.users = {}  # In production, use a database
        
    def create_user(self, username, password, role):
        """Create a new user with password hashing"""
        salt = os.urandom(16)
        
        # Create key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Hash password
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Store user
        self.users[username] = {
            'password_hash': key,
            'salt': salt,
            'role': role,
            'created_at': datetime.datetime.now().isoformat()
        }
        
        return True
    
    def authenticate(self, username, password):
        """Authenticate a user"""
        if username not in self.users:
            return False, "User not found"
            
        user = self.users[username]
        salt = user['salt']
        
        # Create key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Hash provided password
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Compare hashes
        if key != user['password_hash']:
            return False, "Invalid password"
            
        # Generate session token
        session_id = str(uuid.uuid4())
        token = self.generate_token(username, user['role'])
        
        # Store session
        self.sessions[session_id] = {
            'username': username,
            'role': user['role'],
            'created_at': datetime.datetime.now().isoformat(),
            'token': token
        }
        
        return True, {
            'session_id': session_id,
            'token': token,
            'role': user['role']
        }
    
    def generate_token(self, username, role):
        """Generate JWT token"""
        payload = {
            'username': username,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        return token
    
    def validate_token(self, token):
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, "Token expired"
        except jwt.InvalidTokenError:
            return False, "Invalid token"
    
    def check_permission(self, username, action, resource):
        """Check if user has permission for an action"""
        if username not in self.users:
            return False
            
        role = self.users[username]['role']
        
        # Define permissions by role (in production, use a more sophisticated system)
        permissions = {
            'admin': ['read', 'write', 'delete', 'manage'],
            'investigator': ['read', 'write'],
            'viewer': ['read']
        }
        
        if role not in permissions:
            return False
            
        return action in permissions[role]
