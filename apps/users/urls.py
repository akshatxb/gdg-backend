from django.urls import path
from .views import (
    register_user,
    login_user,
    logout_user,
    test_view,
    token_refresh,
    token_verify,
    TestView,
)

urlpatterns = [
    path("login", login_user, name="login"),
    path("register", register_user, name="register"),
    path("logout", logout_user, name="logout"),
    path("refresh", token_refresh, name="refresh"),
    path("verify", token_verify, name="verify"),
    path("test1", TestView.as_view(), name="test1"),
    path("test2", test_view, name="test2"),
]
