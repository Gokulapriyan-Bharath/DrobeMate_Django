import jwt, datetime,re
from django.conf import settings
from .models import BlacklistedToken

# Generate JWT
def generate_jwt(user_id, hours=24):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=hours),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

# Decode JWT
def decode_jwt(token):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return "invalid"

# Check blacklist
def is_token_blacklisted(token):
    return BlacklistedToken.objects.filter(token=token).exists()

# Extract token
def get_token_from_header(request):
    auth = request.headers.get("Authorization")
    if not auth:
        return None
    return (auth.split(" ")[1])
