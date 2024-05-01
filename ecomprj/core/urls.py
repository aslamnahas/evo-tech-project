from django.urls import path
# from .views import home ,signup , login
from . import views
app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path('signupPage/', views.signupPage, name="signupPage"),
    path('loginPage/', views.loginPage, name='loginPage'), 
    path('google/',views.google, name='google'),
    path('logout/', views.custom_logout, name='custom_logout'),
    path('verify-otp/',views.verify_otp, name='verify_otp'),
    

    path('categories/',views.user_category_view, name='user_categories'),
    path('products/',views.products, name='products'),
    path('products/<int:id>/', views.product_detail, name='product_detail'),



     path('profile/',views.profile,name='profile'),
     path('manage_profile/',views.manage_profile,name='manage_profile'),
   
  
     path('address/',views.address,name='address'),
     path('add_address/',views.add_address,name='add_address'),
     path('update_address/<int:id>',views.update_address,name='update_address'),
     path('delete_address/<int:id>/',views.delete_address,name='delete_address'),
   
    

     path('cart/',views.cart,name='cart'),
     path('update-cart/<int:product_id>/', views.update_cart, name='update_cart'),
     path('add_to_cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
     path('remove_from_cart/<int:cart_item_id>/', views.remove_from_cart, name='remove_from_cart'),

]