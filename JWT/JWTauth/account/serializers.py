from django.forms import ValidationError
from rest_framework import serializers
from account.models import User
from account.utils import Util
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
class UserRegistrationSerializer(serializers.ModelSerializer):
    
    password2=serializers.CharField(style={'input type':'password'}, write_only=True)
    class  Meta:
        model=User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }

  #validating and confirming password
    def validate(self, attrs):        
        password=attrs.get('password')
        password2=attrs.get('password2')
        if(password!=password2):
            raise serializers.ValidationError("Password and confirm password does not match!")
        return attrs   

    def create(self, validate_data):
        return User.objects.create_user(**validate_data)      

class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class  Meta:
        model=User
        fields=['email','password']

class UserProfileSerializer(serializers.ModelSerializer):
    class  Meta:
        model=User
        fields=['id','email','name']        

class UserpasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style={'input type':'password'}, write_only=True)
    password2=serializers.CharField(max_length=255,style={'input type':'password'}, write_only=True)

    class  Meta:        
        fields=['password','password2'] 

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')

        if(password!=password2):
            raise serializers.ValidationError("Password and confirm password does not match!")        
        user.set_password(password)
        user.save()
        return attrs    

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)
    class  Meta:
        model=User
        fields=['email']      

    def validate(self, attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            print('Encoded UID  ',uid)
            print('Password reset Token',token)
            link='http://127.0.0.1:3000/api/user/reset/'+uid+'/'+token
            print('Password reset link',link)
            
            #Send Email
            body='Click following link to reset your password'+ link
            data={
                'subject':'Reset your password',
                'body':body,
                'to_email':user.email
            }
            Util.send_email(data)

            return attrs
        else:
            raise ValidationError('You are not valid user')    

class UserPasswordResetSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=255,style={'input type':'password'}, write_only=True)
    password2=serializers.CharField(max_length=255,style={'input type':'password'}, write_only=True)

    class  Meta:        
        fields=['password','password2'] 

    def validate(self, attrs):
       try:
        password=attrs.get('password')
        password2=attrs.get('password2')
        uid=self.context.get('uid')
        token=self.context.get('token')
        if(password!=password2):
            raise serializers.ValidationError("Password and confirm password does not match!") 
        id= smart_str(urlsafe_base64_decode(uid))
        user=User.objects.get(id=id) 
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise ValidationError('Token is not valid or Expired')          
        user.set_password(password)
        user.save()
        return attrs  
       except DjangoUnicodeDecodeError as identifire:
         PasswordResetTokenGenerator().check_token(user,token)
         raise ValidationError('Token is not valid or Expired')