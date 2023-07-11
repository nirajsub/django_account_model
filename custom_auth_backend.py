from django.contrib.auth.backends import BaseBackend
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.tokens import AccessToken

class TokenAuthenticationBackend(BaseBackend):
    def authenticate(self, request, token=None):
        try:
            if token:
                validated_token = AccessToken(token)
                return self.get_user(validated_token), validated_token
        except (TokenError, InvalidToken):
            pass

    def get_user(self, validated_token):
        user_id = validated_token['user_id']
        try:
            return MainUser.objects.get(user_id=user_id).user
        except MainUser.DoesNotExist:
            pass

    def get_user_from_request(self, request):
        token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        return self.authenticate(request, token=token)

    def authenticate_header(self, request):
        return 'Token'
