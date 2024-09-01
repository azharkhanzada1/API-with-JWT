from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.exceptions import ValidationError

class UserRegistertionSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'tc', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    # Validation Password and Confirm Password Registration
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password2') 
        return User.objects.create_user(**validated_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ["email", "password"]

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')  
        if password != password2:
            raise serializers.ValidationError("password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs
    

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.CharField(max_length = 266)
    class Meta:
        fields = ['email']  

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email = email)
            uuid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UUID : ", uuid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Reset Password Token : ", token)
            link = 'http://127.0.0.1:8000/api/user/reset/'+uuid+'/'+token
            print("Password Reset Link: ", link) 
            body = "Click Following Link to Reset Your Password "+ link
            data = {
                'subject' : "Reset Your Password",
                'body':body,
                'to_email': user.email 
            }
            return attrs
        else:
            raise ValidationError("you are not a Register User")


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, 
        style={'input_type': 'password'}, 
        write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, 
        style={'input_type': 'password'}, 
        write_only=True
    )
    
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get("password2")
        uuid = self.context.get('uuid')
        token = self.context.get('token')

        if password != password2:
            raise serializers.ValidationError("Passwords do not match.")
        
        try:
            # Decode the user's ID from the UUID
            id = smart_str(urlsafe_base64_decode(uuid))
            user = User.objects.get(id=id)

            # Check if the token is valid
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or has expired.")
            
            # If everything is valid, set the new password
            user.set_password(password)
            user.save()
            return attrs


        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')

