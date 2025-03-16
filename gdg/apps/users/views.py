import uuid
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import (
    TokenError,
    ExpiredTokenError,
    InvalidToken,
)
from rest_framework.permissions import AllowAny
from codes import expired_token, invalid_token, no_token
import logging

logger = logging.getLogger(__name__)


class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        token = request.COOKIES.get("refresh")

        if not token:
            return Response(
                {"message": "Refresh token is required", "error": no_token},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            refresh = RefreshToken(token)
            access = str(refresh.access_token())

            response = Response({"message": "User Verified"}, status=status.HTTP_200_OK)
            response.set_cookie(
                key="access",
                value=access,
                httponly=False,
                secure=True,
                samesite="None",
            )

            return response

        except ExpiredTokenError:
            return Response(
                {"message": "Refresh token expired", "error": expired_token},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except InvalidToken:
            return Response(
                {"message": "Invalid refresh token", "error": invalid_token},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            logger.debug(e)
            return Response(
                {"message": "Unexpected Server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AccessTokenVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        token = request.COOKIES.get("access")

        if not token:
            return Response(
                {"message": "Access token is required", "error": no_token},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            AccessToken(token)
            return Response({"message": "User Verified"}, status=status.HTTP_200_OK)
        except ExpiredTokenError:
            return Response(
                {"message": "Access token expired", "error": expired_token},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except InvalidToken:
            return Response(
                {"message": "Invalid access token", "error": invalid_token},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as e:
            logger.debug(e)
            return Response(
                {"message": "Unexpected Server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@api_view(["POST"])
def register_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email:
        return Response(
            {"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    elif not password:
        return Response(
            {"message": "Password is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        if User.objects.filter(email=email).exists():
            return Response(
                {"message": "Email already in use."}, status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.create_user(
            username=uuid.uuid4(), email=email, password=password
        )
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

        response = Response(
            {
                "message": "Register Successful",
                "user": user.username,
            },
            status=status.HTTP_200_OK,
        )

        response.set_cookie(
            key="access",
            value=access,
            httponly=False,
            secure=True,
            samesite="None",
        )

        response.set_cookie(
            key="refresh",
            value=str(refresh),
            httponly=False,
            secure=True,
            samesite="None",
        )

        return response

    except TokenError:
        logger.debug(e)
        return Response(
            {"message": "Internal Server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception as e:
        logger.debug(e)
        return Response(
            {"message": "Internal Server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
def login_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if not email:
        return Response(
            {"message": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
        )
    elif not password:
        return Response(
            {"message": "Password is required."}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)
        valid_user = authenticate(username=user.username, password=password)

        if valid_user is not None:
            login(request, valid_user)

            refresh = RefreshToken.for_user(valid_user)
            access = str(refresh.access_token)
            response = Response(
                {
                    "message": "Login Successful",
                    "user": user.username,
                },
                status=status.HTTP_200_OK,
            )

            response.set_cookie(
                key="access",
                value=access,
                httponly=False,
                secure=True,
                samesite="None",
            )

            response.set_cookie(
                key="refresh",
                value=str(refresh),
                httponly=False,
                secure=True,
                samesite="None",
            )

            return response
        else:
            return Response(
                {"message": "Invalid Credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    except User.DoesNotExist:
        return Response(
            {"message": "User does not exist."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    except TokenError:
        logger.debug(e)
        return Response(
            {"message": "Internal Server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    except Exception as e:
        logger.debug(e)
        return Response(
            {"message": "Internal Server error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@api_view(["POST"])
def logout_user(request):
    refresh = request.COOKIES.get("refresh")
    if not refresh:
        return Response(
            {"message": "Refresh token required", "error": no_token},
            status=status.HTTP_400_BAD_REQUEST,
        )
    else:
        try:
            token = RefreshToken(refresh)
            token.blacklist()

            response = Response(
                {"message": "User logged out successfully."}, status=status.HTTP_200_OK
            )

        except TokenError as e:
            logger.debug(e)
            response = Response(
                {"message": "Invalid token. User Logged out."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        except Exception as e:
            logger.debug(e)
            response = Response(
                {"message": "Unexpected Server error. User logged out."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        response.delete_cookie(
            key="access",
            samesite="None",
        )

        response.delete_cookie(
            key="refresh",
            samesite="None",
        )

        return response
