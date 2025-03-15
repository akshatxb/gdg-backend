from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import uuid
from rest_framework_simplejwt.tokens import RefreshToken


@api_view(["POST"])
def register_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    if User.objects.filter(email=email).exists():
        return Response(
            {"message": "Email already in use."}, status=status.HTTP_400_BAD_REQUEST
        )
    user = User.objects.create_user(
        username=uuid.uuid4(), email=email, password=password
    )
    refresh = RefreshToken.for_user(user)
    access = str(refresh.access_token)

    return Response(
        {
            "message": "Login Successful",
            "user": user.username,
            "accessToken": access,
            "refreshToken": str(refresh),
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
def login_user(request):
    email = request.data.get("email")
    password = request.data.get("password")

    try:
        user = User.objects.get(email=email)
        valid_user = authenticate(username=user.username, password=password)

        if valid_user is not None:
            login(request, valid_user)

            refresh = RefreshToken.for_user(valid_user)
            access = str(refresh.access_token)
            return Response(
                {
                    "message": "Login Successful",
                    "user": user.username,
                    "accessToken": access,
                    "refreshToken": str(refresh),
                },
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(
                {"message": "Login Failed. Invalid Credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

    except User.DoesNotExist:
        return Response(
            {"message": "Invalid Credentials. User does not exist."},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
def logout_user(request):
    try:
        refresh = request.data.get("refreshToken")
        if not refresh:
            return Response(
                {"message : Refresh token required"}, status=status.HTTP_400_BAD_REQUEST
            )
        else:
            token = RefreshToken(refresh)
            token.blacklist()

            return Response(
                {"message": "User logged out successfully."}, status=status.HTTP_200_OK
            )
    except Exception as e:
        return Response(
            {"message": "Unexpected internal error"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
