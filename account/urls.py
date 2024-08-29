from django.urls import path, include
from account.views import UserRegistertionView, UserLoginView, UserProfileView, UserChangePasswordView, SendPasswordEmailView
urlpatterns = [
    path('register/', UserRegistertionView.as_view(), name="register"),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='prodile'),
    path('change-password/', UserChangePasswordView.as_view(), name='change-password'),
    path('reset-password/', SendPasswordEmailView.as_view(), name="reset-password"),

]