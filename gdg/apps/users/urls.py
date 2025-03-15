from django.urls import path
from .views import register_user, login_user, logout_user
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("login", login_user, name="login"),
    path("register", register_user, name="register"),
    path("logout", logout_user, name="logout"),
    path("refresh", TokenRefreshView.as_view(), name="refresh"),
]
