from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import HTTP_HEADER_ENCODING


class CookieJWTAuthentication(JWTAuthentication):

    def get_header(self, request) -> bytes:
        token = request.COOKIES.get("access")
        if token:
            auth_header = f"Bearer {token}"
            return auth_header.encode(HTTP_HEADER_ENCODING)
        return None
    
    def authenticate(self, request):
        return super().authenticate(request)
