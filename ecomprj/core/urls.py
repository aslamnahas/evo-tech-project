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
    path('categories/<int:category_id>/products/', views.category_products, name='category_products'), 
    # path('search/', views.user_category_view, name='search'),



     path('profile/',views.profile,name='profile'),
     path('manage_profile/',views.manage_profile,name='manage_profile'),
     path('change_password/', views.change_password, name='change_password'),
   
  
     path('address/',views.address,name='address'),
     path('add_address/',views.add_address,name='add_address'),
     path('update_address/<int:id>',views.update_address,name='update_address'),
     path('delete_address/<int:id>/',views.delete_address,name='delete_address'),
   
    

     path('cart/',views.cart,name='cart'),
     path('update-cart/<int:product_id>/', views.update_cart, name='update_cart'),
     path('add_to_cart/<int:product_id>/', views.add_to_cart, name='add_to_cart'),
     path('remove_from_cart/<int:cart_item_id>/', views.remove_from_cart, name='remove_from_cart'),



    path('wishlist/',views.wishlist, name='wishlist'),
    path('addtowishlist/<int:product_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('remove_from_wishlist/<int:wishlist_item_id>/', views.remove_from_wishlist, name='remove_from_wishlist'),
    path('wishlist_count/', views.wishlist_count, name='wishlist_count'),

    path('checkout',views.checkout,name='checkout'),
    path('placeorder/',views.place_order,name='place_order'),
    path('customerorder/',views.customer_order,name = 'customer_order'),
    path('success/',views.success,name='success'),
    path('cancel_success/',views.cancel_success,name='cancel_success'),
    path('cancel/<int:order_id>/', views.cancel, name='cancel'),
    path('order_details/<int:id>',views.order_details,name='order_details'),
    
    


    path('order/',views.order,name = 'order'),
    path('update_order/', views.updateorder, name='update_order'),
    path('return-order/<int:order_id>/<int:order_item_id>/', views.return_order, name='return_order'),

    path('sort/',views.sort,name='sort'),
    path('search/', views.product_search, name='product_search'),
    path('coupon/',views.coupon,name = 'coupon'),
    path('addcoupon/',views.addcoupon,name='addcoupon'),
    path('delete_coupon/<int:coupon_id>/', views.delete_coupon, name='delete_coupon'),

    path('apply_coupon/', views.apply_coupon, name='apply_coupon'),


    path('wallet/',views.wallet,name='wallet'),
    # path('razorpay/<int:address_id>/',views.razorpay,name='razorpay'),
    # path('proceed-to-pay',views.proceedtopay,name='proceedtopay'),
    # path('razorpay/<int:address_id>/',views.razorpay,name='razorpay'),
    path('create-razorpay-order/',views.create_razorpay_order, name='create_razorpay_order'),

    path('generate_invoice/<int:order_id>/', views.generate_invoice, name='generate_invoice'),
    path('<int:order_id>/download/', views.download_invoice, name='download_invoice'),

    path('new/', views.new, name='new'),

]