from django.shortcuts import render
from django.contrib.admin import action
from rest_framework.decorators import (
    api_view,
    permission_classes,
    authentication_classes,
)
from rest_framework.response import Response
from rest_framework import status


@api_view(["POST"])
def test_veiw(request):
    print("Test View Hit.")

    return Response(
        {"message": "Test View Hit.", "error": "no_token"}, status=status.HTTP_200_OK
    )
