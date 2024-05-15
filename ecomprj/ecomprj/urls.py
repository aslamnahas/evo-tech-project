"""
URL configuration for ecomprj project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from  core.views import *

urlpatterns = [
    path('admin/', admin.site.urls),


    path('',include("core.urls")),
    path('adminn/',include('admin_side.urls')),
    path('map/',include("map.urls")),
    path('accounts/',include('allauth.urls')),
    path('razorpay/<int:address_id>/',razorpay,name='razorpay'),
    path('proceed-to-pay/',proceedtopay,name='proceedtopay'),
    # path('razorpay/<int:address_id>/',razorpay,name='razorpay'),
    # path('create-razorpay-order/<int:wallet_id>/',create_razorpay_order, name='create_razorpay_order'),
    path('wallet/', wallet, name='wallet'),
    path('create-razorpay-order/', create_razorpay_order, name='create_razorpay_order'),

    path('create-razorpay-order/<int:wallet_id>/', create_razorpay_order, name='create_razorpay_order'),

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
