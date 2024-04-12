from django.contrib import admin
from .views import *
from django.urls import path,include
from rest_framework.routers import DefaultRouter

router = DefaultRouter()


urlpatterns = [
    path('api/', include(router.urls)),
    path('admin/', admin.site.urls),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('signup/',Signup.as_view(),name='signup'),
    path('verify-token/',VerifyTokenView.as_view(), name='verify-token'),
    path('get-user-details/', GetUserDetails.as_view(), name='user_details'),
    path('forgotpassword/', ForgotPasswordAPIView.as_view(),name='forgotpassword'),
    path('resetpassword/<uidb64>/<token>/',ResetPasswordAPIView.as_view(), name='resetpassword'),
    path('changepassword/', changePassword.as_view(), name='changepassword'),
    path('test/', TestData.as_view(), name='test'),
    path('shuffle/', shuffle.as_view(), name='shuffle'),
    path('result/', Resultsubmit.as_view(), name='result'),
    path('csu/', create_super_user,name='csu'),
]