
from django.shortcuts import render, redirect ,HttpResponse
from django.contrib.auth import authenticate, login, logout
from core.models import Main_Category ,Product
from .manager import BaseUserManager
from .models import Customer ,Address
from django.shortcuts import get_object_or_404
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
import os
from django.core.validators import RegexValidator
import math
from django.core.exceptions import ValidationError
from django.urls import reverse
import random
import smtplib
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.views.decorators.cache import never_cache,cache_control
from django.http.response import JsonResponse
from . models import *
from django.http import JsonResponse, HttpResponseRedirect
from django.http import JsonResponse
import json
from django.contrib.auth.models import AnonymousUser
from django.views.decorators.csrf import csrf_exempt
from django.http import Http404
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import update_session_auth_hash
from django.db.models import Q
from decimal import Decimal
from random import shuffle
from datetime import date
from django.db.models import Count, Avg
from django.template.loader import get_template
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator

#=============================otp=========================================================

def send_otp(email):
    try:
        digits = "0123456789"
        OTP = "".join(random.choices(digits, k=6))

        msg = MIMEMultipart()
        msg['From'] = 'aslamthayamkulam@gmail.com'
        msg['To'] = email
        msg['Subject'] = 'Your OTP'

        body = OTP + " is your OTP"
        msg.attach(MIMEText(body, 'plain'))

        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()
        s.login("aslamthayamkulam@gmail.com", "hrsg bfcm yfot zryk")
        s.sendmail('aslamthayamkulam@gmail.com', email, msg.as_string())
        s.quit()

        print(f"OTP sent to {email}: {OTP}")
        return OTP
    except Exception as e:
        print(f"Failed to send OTP to {email}: {str(e)}")
        return None
#=====================================================signup===============================#   
def signupPage(request):
    if 'email' in request.session:
        return redirect('core:home')

    if request.method == 'POST':
        email     =    request.POST.get('email')
        ph_no    =    request.POST.get('ph_no')
        username  =    request.POST.get('username')
        pass1     =    request.POST.get('password1')
        pass2     =    request.POST.get('password2')
        
        if all(not field.strip() for field in [email, ph_no, pass1, pass2]) or not username.strip():
          messages.error(request, 'Please input non-whitespace characters in all fields.')
          return redirect('core:signupPage')

        if not email or not username or not pass1 or not pass2:
            messages.error(request, 'Please input all the details.')
            return redirect('core:signupPage')

        if pass1 != pass2:
            messages.error(request, 'Passwords do not match.')
            return redirect('core:signupPage')

        if not validate_email(email):
            messages.error(request, 'Please enter a valid email address.')
            return redirect('core:signupPage')

        if Customer.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return redirect('core:signupPage')
       
        if Customer.objects.filter(email=email).exists():
            messages.error(request, 'Email already exist')
            return redirect('core:signupPage')
        if Customer.objects.filter(ph_no=ph_no).exists():
            messages.error(request, 'Number already exist')
            return redirect('core:signupPage')
 
        user = Customer.objects.create_user(username=username, password=pass1, email=email, ph_no=ph_no)
        user.save()

        otp = send_otp(email)
        if otp:
            request.session['email'] = email
            request.session['otp'] = otp
            request.session['otp_time'] = time.time()  # Track OTP generation time
            messages.success(request, 'OTP is sent to your email')
            print(f"Signup OTP: {otp}")
            return redirect('core:verify_otp')
        else:
            messages.error(request, 'Failed to send OTP. Please try again.')
            return redirect('core:signupPage')

    return render(request, 'core/registration.html')


     # ......... End Signup .............
import time

# Modify the verify_otp function to include OTP resend functionality
def verify_otp(request):
    if request.method == 'POST':
        if 'resend_otp' in request.POST:
            email = request.session.get('email')
            if email:
                otp = send_otp(email)
                if otp:
                    request.session['otp'] = otp
                    request.session['otp_time'] = time.time()  # Reset the OTP timer
                    messages.success(request, "OTP resent successfully!")
                    print(f"Resent OTP: {otp}")
                else:
                    messages.error(request, "Failed to resend OTP. Please try again.")
                return redirect('core:verify_otp')

        entered_otp = request.POST.get('otp')
        stored_otp = request.session.get('otp')
        otp_time = request.session.get('otp_time')

        if not entered_otp or not stored_otp or not otp_time:
            messages.error(request, "Invalid OTP.")
            return redirect('core:verify_otp')

        if time.time() - otp_time > 300:  # Expiration time set to 5 minutes (300 seconds)
            messages.error(request, "OTP has expired. Please request a new OTP.")
            return redirect('core:verify_otp')

        if entered_otp == stored_otp:
            del request.session['otp']
            del request.session['otp_time']
            del request.session['email']
            messages.success(request, "Signup successful! You can now log in.")
            return redirect('core:loginPage')
        else:
            messages.error(request, "Incorrect OTP, please try again.")

    return render(request, "core/otp_user.html")
#===============================loginpage================================================#
@never_cache
def loginPage(request):
    context = {
        'messages': messages.get_messages(request)
    }
    # if 'email' in request.session:
    #     return redirect('core:home')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Authenticate the user
        user = authenticate(request, email=email, password=password)
        
        if user is not None:
            # Check if the user is blocked
            if user.is_blocked:
                    messages.error(request, 'Your account is blocked.')
                    return redirect('core:loginPage')
                
            # If not blocked, proceed with login
            request.session['email'] = email
            login(request, user)
            messages.success(request, "Login successful. Welcome back!")
            return redirect('core:home')
        else:
            messages.error(request, "Username or password is incorrect")
            return render(request, 'core/userlogin.html', context)
    else:
        # Clear any previous session data
        request.session.flush()
        return render(request, 'core/userlogin.html', context)

def validate_email(email):
    return '@' in email and '.' in email
#=====================logout===================================#
def custom_logout(request):
    print(request.user)
    logout(request)
    return redirect('core:home')

#=======================forgotpassword================================#
import smtplib
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Customer
import secrets
from django.contrib.auth.tokens import default_token_generator
# from d# core/views.py
# core/views.py
# core/views.py

import smtplib
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import authenticate, login
from .models import Customer
import secrets

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            customer = Customer.objects.get(email=email)
            if customer.email == email:
                message = generate_otp()
                sender_email = "aslamthayamkulam@gmail.com"
                receiver_mail = email
                password = "hrsg bfcm yfot zryk"

                try:
                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login(sender_email, password)
                        server.sendmail(sender_email, receiver_mail, message.encode('utf-8'))

                    request.session['email'] = email
                    request.session['otp'] = message
                    print(message)
                    messages.success(request, 'OTP is sent to your email')
                    uidb64 = urlsafe_base64_encode(force_bytes(customer.pk))
                    token = default_token_generator.make_token(customer)

                    return redirect('core:reset_password', uidb64=uidb64, token=token)

                except smtplib.SMTPAuthenticationError:
                    messages.error(request, 'Failed to send OTP email. Please check your email configuration.')
                    return redirect('core:signupPage')

        except Customer.DoesNotExist:
            messages.info(request, "Email is not valid")
            return redirect('core:loginPage')
    else:
        return render(request, 'core/forgot_password.html')

def generate_otp(length=6):
    return ''.join(secrets.choice("0123456789") for i in range(length))

def reset_password(request, uidb64, token):
    print(f"uidb64: {uidb64}, token: {token}")
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        customer = Customer.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Customer.DoesNotExist):
        customer = None

    if customer is not None and default_token_generator.check_token(customer, token):
        if request.method == 'POST':
            entered_otp = request.POST.get('otp')
            new_password = request.POST.get('new_password')
            print(new_password,'newwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww')
            confirm_password = request.POST.get('confirm_password')
            stored_otp = request.session.get('otp')

            if entered_otp == stored_otp:
                if new_password == confirm_password:
                    customer.set_password(new_password)
                    customer.save()
                    del request.session['otp']
                    messages.success(request, 'Password reset successful. Please login with your new password.')
                    print(f"New password set for user {customer.email}.")
                    return redirect('core:loginPage')
                else:
                    messages.error(request, 'New password and confirm password do not match.')
            else:
                messages.error(request, 'Invalid OTP. Please enter the correct OTP.')

            context = {
                'uidb64': uidb64,
                'token': token,
            }
            return render(request, 'core/passwordreset.html', context)
        else:
            context = {
                'uidb64': uidb64,
                'token': token,
            }
            return render(request, 'core/passwordreset.html', context)
    else:
        messages.error(request, 'Invalid password reset link.')
        return redirect('core:loginPage')

#=================================google===================================#
def google(request):

      context = {
        'provider': 'Google'  # You can dynamically determine the provider here
     }
      return render(request,'core/google.html',context)

# ============================categories user side============================================#


def user_category_view(request):
    categories = Main_Category.objects.filter(deleted=False)  # Fetch active categories
    return render(request, 'core/user_categories.html', {'categories': categories})

#==============================products view user  ==============================#
def products(request):
    # Get all products that are not deleted
    product_list = Product.objects.filter(deleted=False)

    # Filter products based on category
    category_id = request.GET.get('category')
    if category_id:
        product_list = product_list.filter(main_category_id=category_id)

    # Filter products based on price range
    price_range = request.GET.get('price_range')
    if price_range:
        min_price, max_price = map(int, price_range.split('-'))
        product_list = product_list.filter(price__range=(min_price, max_price))

    # Filter products based on color
    color_range = request.GET.get('color_range')
    # print("Color range:", color_range)  # Debugging print statement
    if color_range:
        product_list = product_list.filter(color=color_range)
    # print(product_list)

    # Order products by ID (you can change the ordering as needed)
    product_list = product_list.order_by('-id')

    # Paginate the filtered product list
    paginator = Paginator(product_list, 9)  # Show 9 products per page

    page_number = request.GET.get('page')
    try:
        products = paginator.page(page_number)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        products = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        products = paginator.page(paginator.num_pages)

    return render(request, 'core/products.html', {'products': products})
# productshowing page======================================================================

def product_detail(request, id):
    # Get the product and its variants
    product = get_object_or_404(Product, id=id)
    discounted_price = product.get_discounted_price()
    # Fetch additional images from the related ProductImage model
    additional_images =  product.additional_images.all()
    # Fetch similar products based on the main category
    similar_products = Product.objects.filter(
    main_category=product.main_category  # Filter similar products by main category
    ).exclude(id=product.id).order_by('?')  # Exclude the current product and randomize the order
    reviews = Review.objects.filter(product=product)
   
    form = ReviewForm()
  
    if reviews.exists():
        avg_rating = reviews.aggregate(Avg('rating'))['rating__avg']
        
    else:
        avg_rating = 0 

    full_stars = int(avg_rating)
    half_star = 1 if avg_rating - full_stars >= 0.5 else 0
    empty_stars = 5 - full_stars - half_star

    full_stars_range = range(full_stars)
    empty_stars_range = range(empty_stars)
    
    context = {
        "product": product,
        "additional_images": additional_images,
        "similar_products": similar_products,
        "discounted_price": discounted_price,
        "reviews": reviews,
        'avg_rating': avg_rating,
        'avg_rating': avg_rating,
        'full_stars': full_stars,
        'full_stars_range': full_stars_range,

        'half_star': half_star,
        'empty_stars': empty_stars,
        'empty_stars_range': empty_stars_range,
        'form': form,

    }
    return render(request, "core/product_details.html", context)

#=============================user profile details===================================#

from django.db.models import Sum
from decimal import Decimal

def profile(request):
     if request.user.is_authenticated:
        # Fetch wallet balance for the current user
        wallet_balance = Wallet.objects.filter(user=request.user).aggregate(total_balance=Sum('amount'))['total_balance'] or Decimal('0.00')
        return render(request, 'core/profile_user.html', {'wallet_balance': wallet_balance})
     else:
        return render(request, 'core/profile_user.html')
#========================================profile editting=================================#
@login_required
def manage_profile(request):
    if request.method == 'POST':
        # Get user object
        user = request.user
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone = request.POST.get('phone')

        # Check for empty fields
        if not ( username and email and phone):
            messages.error(request, 'Please fill in all the required fields.')
            return redirect(reverse('core:manage_profile'))
        try:
            phone_validator(phone)

        except ValidationError:
            
            messages.error(request, 'Invalid phone number format.')
          

            return redirect(reverse('core:manage_profile'))    

        # Update user profile information
        user.username = username
        user.email = email
        user.ph_no = phone

        # Update user model
        user.save()

        messages.success(request, 'Profile updated successfully!')
        return redirect(reverse('core:profile'))
    
    
    return render(request, 'core/profile_manage.html', {'user': request.user })




phone_validator = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',  # Customize the regex pattern as needed
    message='Enter a valid phone number.',
)

#==================================addresss details,-add address ,-- update udress===========================================#

def address(request):
    data = Address.objects.filter(user=request.user)
    return render(request, 'core/address.html', {'data': data})

def add_address(request):
    if request.method == 'POST':
        user = request.user
        default = request.POST.get('default', False) == 'True'
        address_name = request.POST['address_name']
        address_1 = request.POST['address_1']
        address_2 = request.POST['address_2']
        country = request.POST['country']
        state = request.POST['state']
        city = request.POST['city']
        pin = request.POST['pin']

        # Check for whitespace-only values
        if any(value.strip() == '' for value in [address_name, address_1, address_2, country, state, city, pin]):
            messages.error(request, 'Whitespace-only values are not allowed.')
            return redirect('core:add_address')

        # Check for empty values
        if not address_name or not address_1 or not country or not state or not city or not pin:
            messages.error(request, 'Please fill in all the required fields.')
            return redirect('core:add_address')

        query = Address.objects.create(
            user=user,
            default=default,
            address_name=address_name,
            address_1=address_1,
            address_2=address_2,
            country=country,
            state=state,
            city=city,
            pin=pin,
        )
        query.save()
        return redirect('core:checkout')
    return render(request, 'core/add_address.html')



def update_address(request, id):
    data = Address.objects.all()
    address = Address.objects.get(id = id)
    default = request.POST.get('default')
    if request.method == 'POST':
        default = request.POST.get('default', False) == 'True'
        address_name = request.POST['address_name']
        address_1 = request.POST['address_1']
        address_2 = request.POST['address_2']
        country = request.POST['country']
        state = request.POST['state']
        city = request.POST['city']
        pin = request.POST['pin']
        user = request.user

        if default:
            Address.objects.filter(user=user, default=True).update(default=False)

        edit = Address.objects.get(id = id)
        edit.default = default
        edit.address_name = address_name
        edit.address_1 = address_1
        edit.address_2 = address_2
        edit.country = country
        edit.state = state
        edit.city = city
        edit.pin = pin
        edit.save()
        
        return redirect('core:address')
    context = {
           "address": address,
            "data" : data
            }

    return render(request, 'core/update_address.html', context)


def delete_address(request,id):
    data = Address.objects.get(id=id) 
    data.delete = data.deleted
    data.save
    return redirect('core:address')


def addressmain(request):
    data = Address.objects.filter(user=request.user)
    return render(request,'core/addressmain.html', {'data': data})



def mainadd_address(request):
    if request.method == 'POST':
        user = request.user
        default = request.POST.get('default', False) == 'True'
        address_name = request.POST['address_name']
        address_1 = request.POST['address_1']
        address_2 = request.POST['address_2']
        country = request.POST['country']
        state = request.POST['state']
        city = request.POST['city']
        pin = request.POST['pin']

        # Check for whitespace-only values
        if any(value.strip() == '' for value in [address_name, address_1, address_2, country, state, city, pin]):
            messages.error(request, 'Whitespace-only values are not allowed.')
            return redirect('core:mainadd_address')

        # Check for empty values
        if not address_name or not address_1 or not country or not state or not city or not pin:
            messages.error(request, 'Please fill in all the required fields.')
            return redirect('core:mainadd_address')

        query = Address.objects.create(
            user=user,
            default=default,
            address_name=address_name,
            address_1=address_1,
            address_2=address_2,
            country=country,
            state=state,
            city=city,
            pin=pin,
        )
        query.save()
        return redirect('core:address')
    return render(request, 'core/mainadd_address.html')



#===============================change password==============================================#
@login_required
def change_password(request):
    if request.method == 'POST':
        old_password = request.POST.get('old')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')

        user = request.user

        # Check if the user is authenticated (not AnonymousUser)
        if not user.is_anonymous:
            # Check if the old password matches the user's current password
            if user.check_password(old_password):
                # Check if the new passwords match
                if new_password1 == new_password2:
                    # Set the new password for the user
                    user.set_password(new_password1)
                    user.save()

                    # Update the session to prevent the user from being logged out
                    update_session_auth_hash(request, user)

                    messages.success(request, 'Password reset successful.')
                    return redirect('core:profile')
                else:
                    messages.error(request, 'New password and confirm password do not match.')
            else:
                messages.error(request, 'Old password is incorrect.')
        else:
            messages.error(request, 'User is not authenticated.')

    return redirect('core:profile')
#========================cart===============================================#
@login_required(login_url='core:loginPage') 
def cart(request):
    if isinstance(request.user, AnonymousUser):
        device_id = request.COOKIES.get("device_id")
        cart_items = Cart.objects.filter(device=device_id).order_by("id")
    else:
        user = request.user
        cart_items = Cart.objects.filter(user=user).order_by("id")

    subtotal = 0
    for cart_item in cart_items:
        if cart_item.quantity > cart_item.product.stock:
            messages.warning(request, f"{cart_item.product} is out of stock.")
            cart_item.quantity = cart_item.product.stock
            cart_item.save()

        cart_item.total_price = cart_item.quantity * cart_item.product.get_discounted_price()
        cart_item.save()
        subtotal += cart_item.total_price

    if request.method == "POST":
        if 'remove_coupon' in request.POST:
            # Remove coupon from session
            if "discount" in request.session:
                del request.session["discount"]
                messages.success(request, "Coupon removed successfully.")
        else:
            # Apply coupon logic
            coupon_code = request.POST.get("coupon_code")
            try:
                coupon = Coupon.objects.get(coupon_code=coupon_code, max_usage_count=1)
                if subtotal >= coupon.min_amount:
                    request.session['discount'] = coupon.discount_amount
                    messages.success(request, "Coupon applied successfully.")
                else:
                    messages.error(request, f"Total amount is below the minimum required ({coupon.min_amount}) for this coupon.")
            except Coupon.DoesNotExist:
                messages.error(request, "Invalid or expired coupon code.")
            

    total_discount = request.session.get('discount', 0)
    total = subtotal - total_discount

    request.session['cart_subtotal'] = str(subtotal)  
    request.session['cart_total'] = str(total)
    
    
    coupons = Coupon.objects.all()

    context = {
        "cart_items": cart_items,
        "subtotal": subtotal,
        "total": total,
        "coupons": coupons,
    }

    return render(request, "core/cart.html", context)
#======================add to cart ====================================#
@login_required(login_url='core:loginPage') 
def add_to_cart(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return redirect('product_not_found')
    product = get_object_or_404(Product, id=product_id)
    quantity = request.POST.get('quantity', 1)
    if not quantity:
        quantity = 1

    if not quantity:
        quantity = 1
    # Check if the requested quantity is greater than the available stock
    if int(quantity) > product.stock:
        messages.error(request, f"Insufficient stock for {product.product_name}.")
        return redirect('userproduct')
    
    cart_item, created = Cart.objects.get_or_create(user=request.user, product=product)
    if created:
        cart_item.quantity = int(quantity)
    else:
        cart_item.quantity += int(quantity)
    cart_item.save()
    return redirect('core:cart')
#==============================updatecart=============================#
def update_cart(request, product_id):
    print(f"Updating cart for product ID: {product_id}")
    try:
        data = json.loads(request.body)
        quantity = int(data.get('quantity'))
    except (json.JSONDecodeError, ValueError, TypeError):
        return JsonResponse({'message': 'Invalid quantity.'}, status=400)
    if quantity < 1:
        return JsonResponse({'message': 'Quantity must be at least 1.'}, status=400)

    user = request.user
    cart_item = get_object_or_404(Cart, product_id=product_id, user=user)
    cart_item.quantity = quantity
    cart_item.save()
    return JsonResponse({'message': 'Cart item updated.'}, status=200)
#===============================remove cart=============================================#
@login_required
def remove_from_cart(request, cart_item_id):
        try:
            cart_item = Cart.objects.get(id=cart_item_id, user=request.user)
            cart_item.delete()

        except Cart.DoesNotExist:
            print("Cart doesn't Exist!")
        
        return redirect('core:cart')
#====================================favuraite all ==================================#

@login_required(login_url='loginPage') 
def wishlist(request):
    user = request.user
    if user.is_authenticated:
        wishlist_items = Wishlist.objects.filter(user=user)
        wishlist_count = wishlist_items.count()
        context = {
            'wishlist_items': wishlist_items,
            'wishlist_count': wishlist_count,
        }
        return render(request, 'core/wishlist.html', context)
    else:
        # Redirect to login if user is not authenticated
        return redirect('loginPage')

@login_required(login_url='loginPage')
def wishlist_count(request):
    user = request.user
    if user.is_authenticated:
        wishlist_items = Wishlist.objects.filter(user=user)
        wishlist_count = wishlist_items.count()
        return JsonResponse({'wishlist_count': wishlist_count})
    else:
        # Redirect to login if user is not authenticated
        return redirect('loginPage')

@login_required(login_url='loginPage')
def add_to_wishlist(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return redirect('product_not_found')
    
    user = request.user
    if user.is_authenticated:
        wishlist, created = Wishlist.objects.get_or_create(product=product, user=user)
        wishlist.save()
        return redirect('core:wishlist')
    else:
        # Redirect to login if user is not authenticated
        return redirect('loginPage')

@login_required(login_url='loginPage')
def remove_from_wishlist(request, wishlist_item_id):
    wishlist_item = get_object_or_404(Wishlist, id=wishlist_item_id, user=request.user)
    wishlist_item.delete()
    return redirect('core:wishlist')
#=======================================checkout =========================================#



# @cache_control(no_cache=True, must_revalidate=True, no_store=True)

@never_cache
@login_required(login_url='loginPage')
def checkout(request):
    if request.method == 'POST':
        address_id = request.POST.get('addressId')
        payment_type = request.POST.get('payment')

        if not address_id:
            messages.error(request, "Please select an address.")
            return redirect('core:checkout')

        if not payment_type:
            messages.error(request, "Please select a payment method.")
            return redirect('core:checkout')

        # Add the rest of your order processing logic here...

    user = request.user
    cart_items = Cart.objects.filter(user=user)
    subtotal = 0

    for cart_item in cart_items:
        if cart_item.quantity > cart_item.product.stock:
            messages.warning(
                request, f"{cart_item.product.product_name} is out of stock."
            )
            cart_item.quantity = cart_item.product.stock
            cart_item.save()
            return redirect('core:cart')

    for cart_item in cart_items:
        if cart_item.product:
            itemprice2 = cart_item.product.get_discounted_price() * cart_item.quantity
            subtotal += itemprice2  
        else:
            itemprice2 = cart_item.product.get_discounted_price() * cart_item.quantity
            subtotal += itemprice2  

    carttotal = request.session.get('cart_total', 0)

    # city_distance = CityDistance.objects.filter(user=request.user).first()        
    # if city_distance:
    #     distance_in_km = city_distance.distance

    #     if distance_in_km <= 100:
    #         shipping_cost = 50
    #     elif distance_in_km <= 500:
    #         shipping_cost = 100
    #     elif distance_in_km <= 1000:
    #         shipping_cost = 150
    #     else:
    #         shipping_cost = 200
    # else:
    shipping_cost = 50

    couponamt = request.session.get('discount', 0)
    total = subtotal + shipping_cost - couponamt

    request.session['shipping'] = shipping_cost
    request.session['subtotal'] = str(subtotal)
    request.session['total'] = str(total)

    user_addresses = Address.objects.filter(user=request.user)
    context = {
        'cart_items': cart_items,
        'subtotal': carttotal,
        'total': total,
        'user_addresses': user_addresses,  
        'discount_amount': shipping_cost,
        'couponamt': couponamt  
    }
    return render(request, 'core/checkout.html', context)
 #========================@login_required
def place_order(request):
    user = request.user
    customer = get_object_or_404(Customer, email=user.email)
    cart_items = Cart.objects.filter(user=customer, quantity__gt=0)
    
    if request.method == 'POST':
        address_id = request.POST.get('addressId')
        payment_type = request.POST.get('payment')  
       
        # Check if address and payment type are selected
        if not address_id:  
            messages.error(request, "Please select an address.")
            return HttpResponseRedirect(reverse('core:checkout')) 
        
        if not payment_type:
            messages.error(request, "Please select payment method.")
            return HttpResponseRedirect(reverse('core:checkout'))
      
        in_stock_items = []
        out_of_stock_items = []

        for cart_item in cart_items:
            if cart_item.quantity <= cart_item.product.stock:
                in_stock_items.append(cart_item)
            else:
                out_of_stock_items.append(cart_item)

        # If any item is out of stock, return to cart page
        if out_of_stock_items:
            messages.warning(request, "Some items are out of stock. Please remove them from your cart.")
            return HttpResponseRedirect(reverse('core:cart'))

        subtotal = Decimal(request.session.get('cart_subtotal', 0))
        total_price = subtotal
        
        # Check if total price is above Rs 1000 and payment type is COD
        if total_price > 1000 and payment_type == 'cod':
            messages.error(request, "COD is not available for orders above Rs 1000.")
            return HttpResponseRedirect(reverse('core:checkout'))
        
        # Handle wallet payment
        if payment_type == "wallet":
            total_wallet_balance = Wallet.objects.filter(user=customer).aggregate(total=Sum('amount'))['total']

            wallet = Wallet.objects.filter(user=customer).first()
            if not wallet or total_wallet_balance < total_price:
                messages.warning(request, "Not enough balance in your wallet")
                return HttpResponseRedirect(reverse('core:checkout'))
            wallet.amount -= total_price
            wallet.save()
        
        # Create the order
        order = Order.objects.create(
            user=customer,
            address_id=address_id,
            payment_type=payment_type,
            amount=total_price
        )

        total_quantity = 0
        for cart_item in in_stock_items:
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                image=cart_item.product.image,
            )

            cart_item.product.stock -= cart_item.quantity
            cart_item.product.save()
            total_quantity += cart_item.quantity
            cart_item.delete()

        if payment_type == "wallet":
            Wallet.objects.create(
                user=customer,
                order=order,
                amount=-total_price,
                is_credit=False,
                status="Debited",
            )

        return redirect("core:success")

    return HttpResponseRedirect(reverse('core:checkout'))


def payment_failed(request):
    # Extract any necessary information from the request if needed
    error_message = request.GET.get('error_message', 'Payment failed due to an unknown error.')
    
    # Add the error message to Django messages framework
    messages.error(request, error_message)
    
    # Redirect to the product page or any other desired page
    return redirect('core:products') 

def success(request):
    if "discount" in request.session:
      del request.session["discount"]
    orders = Order.objects.order_by("-id")[:1]
    context = {
        "orders": orders,
    }
    return render(request, "core/placeorder.html", context)



def failed(request):
    orders = Order.objects.order_by("-id")[:1]
    context = {
        "orders": orders,
    }
    return render(request, "core/order_failed.html", context)


def payment_failed(request):
    return render(request, 'core/payment_failed.html')

#=============================orderdetails==========================================#
@login_required
def order_details(request, id):
    order = get_object_or_404(Order, id=id)
    context = {
        'order': order,
        'products': order.order_items.all(),
    }
    return render(request, "core/order_details.html", context)
#=============================user orderlist=====================================#
@login_required
def customer_order(request):
    if request.user.is_authenticated:
        user_orders = Order.objects.filter(user=request.user).order_by('-id')
        return render(request, "core/customer_order.html", {'orders': user_orders})
    else:
        return redirect("core:home")
    
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F

# @login_required

@login_required
def cancel(request, order_id):
    if request.method == 'POST':
        # Get the order object based on the id
        order = get_object_or_404(Order, pk=order_id)
        user = request.user
        customer = get_object_or_404(Customer, email=user.email)

        # Determine the new status of the order
        if order.status in ['pending', 'processing', 'shipped']:
            order.status = 'cancelled'
        else:
            order.status = 'returned'# Keep current status if it's already 'cancelled' or 'returned'

        # Update order status if it's eligible for cancellation
        # if new_status != order.status:
        #     order.status = new_status

            # Iterate through order items to update stock
        for item in order.order_items.all():
            product = item.product
            product.stock = F('stock') + item.quantity
            product.save()

            # Get the user's wallet, if exists
           
        user = request.user
        try:
            wallet = Wallet.objects.get(user=request.user)
        except Wallet.DoesNotExist:
            # If wallet doesn't exist, create one for the user
            wallet = Wallet.objects.create(user=request.user)
        except Wallet.MultipleObjectsReturned:
            # If multiple wallets exist, take the first one
            wallets = Wallet.objects.filter(user=request.user)
            wallet = wallets.first()

        # if order.payment_type == 'COD' and order.status == 'returned':
        #     # Refund the amount to the user's wallet
        #     wallet.amount += order.amount
        #     wallet.save()

        # order.save()  # Save the updated status
        # Add the amount of cancelled order to the wallet balance if order via razorpay
        subtotal=0
        if order.payment_type == 'razorpay' or order.payment_type == 'wallet':
        #    subtotal = Decimal(request.session.get('cart_subtotal', 0))
           wallet = Wallet.objects.create(
                user=user,
                order=order,
                amount=order.amount,
                is_credit=True,
                status="credited"
           )
        order.save()

             # Save the updated status

        # Redirect to the same page or any desired page after status change
        return redirect('core:customer_order')
    else:
        # Handle GET requests appropriately, if needed
        return redirect('core:customer_order')


def cancel_success(request):
    
    orders = Order.objects.order_by("-id")[:1]
    context = {
        "orders": orders,
    }
    return render(request, "core/cancel_order.html", context)


def restock_products(order):
    order_items = OrderItem.objects.filter(order=order)
    for order_item in order_items:
        product = order_item.product
        product.stock += order_item.quantity
        product.save()


#===================================order mgt adminside===================================#
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def order(request):
    # Fetch all orders ordered by creation date in descending order
    orders = Order.objects.order_by('-date')
    context = {
        'orders': orders,
    }
    return render(request, 'adminside/orders.html', context)
   


def updateorder(request):
    if request.method == "POST":
        order_id = request.POST.get("order_id")
        status = request.POST.get("status")
        new_status = request.POST.get("status")
        order = get_object_or_404(Order, id=order_id)

        try:
            order = Order.objects.get(id=order_id)
        except Order.DoesNotExist:
            return redirect("order")
        if new_status == 'cancelled':
            handle_cancellation(order)

        order.status = status
        order.save()
        messages.success(request, "Order status updated successfully.")

        return redirect("core:order")
    
    return redirect("adminside:dashboard")

from decimal import Decimal
from django.utils import timezone

def handle_cancellation(order):
    if order.payment_type == 'razorpay':
        order_items = order.order_items.all()
        total_amount = sum(order_item.product.price * order_item.quantity for order_item in order_items)

        wallet = Wallet.objects.create(
            user=order.user,
            order=order,
            amount=total_amount,
            status="Credited",
            created_at=timezone.now(),
        )
        wallet.save()

        for order_item in order_items:
            product = order_item.product
            product.stock += order_item.quantity
            product.save()

            order.user.wallet_bal += order_item.product.price * order_item.quantity
            order.user.save()
@login_required

def return_order(request, order_id, order_item_id):
    try:
        order = Order.objects.get(id=order_id)
        order_item = OrderItem.objects.get(id=order_item_id, order=order)
    except ObjectDoesNotExist:
        return render(request, 'core/customer_order.html')

    if order_item:
        product = order_item.product
        if product:
            product.stock += order_item.quantity
            product.save()

            user = request.user
            user_customer = get_object_or_404(Customer, email=user.email)
            # returned_amount = order_item.product.price * order_item.quantity
            subtotal=0
            total_price=0
            subtotal = Decimal(request.session.get('cart_subtotal', 0))
            total_price = subtotal
            print(f"Crediting amount: {total_price} to user: {user_customer.email}")  # Debugging statement
            user_customer.wallet_bal += total_price
            user_customer.save()
            print(f"New wallet balance: {user_customer.wallet_bal}")  # Debugging statement

            # Create a new Wallet entry for the refund
            wallet_entry = Wallet.objects.create(
                user=user_customer,
                order=order,
                amount=total_price,
                is_credit=True,
                status="Refund"
            )
            print(f"Wallet entry created: {wallet_entry}")  # Debugging statement

            order_item.delete()

            if not OrderItem.objects.filter(order=order).exists():
                order.status = "Return successful"
                order.save()

    return redirect("core:customer_order")
#=================================sorting==================================#
def sort(request):
    products = Product.objects.filter(deleted=False).order_by('-id')  # Retrieve all products initially

    # Sorting logic
    sort_by = request.GET.get('sort_by')
    if sort_by:
        if sort_by == 'price+':
            products = products.order_by('price')
        elif sort_by == 'price-':
            products = products.order_by('-price')
        elif sort_by == 'name+':
            products = products.order_by('model')
        elif sort_by == 'release_date-':
            products = products.order_by('-id')

    return render(request, 'core/products.html', {'products': products})
#=================================product search=======================================#
def product_search(request):
    if request.method == "POST":
        searched = request.POST.get('searched')
        category_id = request.POST.get('category')

        search_terms = searched.split()
        q_objects = Q()

        for term in search_terms:
            q_objects |= Q(model__icontains=term) | Q(color__icontains=term)

        products = Product.objects.filter(q_objects).distinct()

        if category_id:
            products = products.filter(main_category_id=category_id)

        context = {
            'products': products,
        }
        return render(request, 'core/products.html', context)  # Correct template name here

    main_categories = Main_Category.objects.all()
    return render(request, 'core/base.html', {'main_categories': main_categories})
#======================================couponmanagment===========================================#
@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def coupon(request):
    if  request.user:
        
        coupons = Coupon.objects.all().order_by("id")
        context = {"coupons": coupons}
        return render(request, "adminside/coupon.html", context)
    else:
        
        return redirect("adminside:dashboard")

def addcoupon(request):
    if request.method == "POST":
        # Retrieve form data
        coupon_code = request.POST.get("Couponcode")
        discount_amount = request.POST.get("dprice")
        min_amount = request.POST.get("amount")

        # Check if all fields are provided
        if not (coupon_code and discount_amount and min_amount):
            messages.error(request, "Please provide all coupon details.")
            return redirect("core:coupon")

        # Check if coupon code already exists
        if Coupon.objects.filter(coupon_code=coupon_code).exists():
            messages.error(request, "Coupon code already exists.")
            return redirect("core:coupon")

        try:
            # Attempt to convert discount_amount and min_amount to integers
            discount_amount = int(discount_amount)
            min_amount = int(min_amount)

            # Check if discount_amount and min_amount are positive
            if discount_amount <= 0 or min_amount <= 0:
                messages.error(request, "Discount amount and minimum amount must be positive integers.")
                return redirect("core:coupon")

            # Create new coupon instance
            coupon = Coupon(
                coupon_code=coupon_code,
                discount_amount=discount_amount,
                min_amount=min_amount,
            )

            # Save the coupon
            coupon.save()

            messages.success(request, "Coupon added successfully.")
            return redirect("core:coupon")
        except ValueError:
            # If discount_amount or min_amount cannot be converted to integers
            messages.error(request, "Discount amount and minimum amount must be integers.")
            return redirect("core:coupon")
    else:
        return redirect("adminside:dashboard")

def delete_coupon(request, coupon_id):
    if request.method == "POST":
        # Get the coupon object
        coupon = get_object_or_404(Coupon, id=coupon_id)
        # Delete the coupon
        coupon.delete()
        # Redirect to the coupon page
        return redirect("core:coupon")
    else:
        # If request method is not POST, redirect to dashboard
        return redirect("adminside:dashboard")

def apply_coupon(request):
    if request.method == "POST":
        coupon_code = request.POST.get("coupon_code")

        try:
            coupon = Coupon.objects.get(coupon_code=coupon_code)
        except Coupon.DoesNotExist:
            messages.error(request, "Invalid coupon code")
            return redirect("checkout")

        user = request.user
        cart_items = Cart.objects.filter(user=user)
        subtotal = 0
        shipping_cost = 10
        total_dict = {}
        coupons = Coupon.objects.all()


        for cart_item in cart_items:
            if cart_item.quantity > cart_item.product.stock:
                messages.warning(
                    request, f"{cart_item.product.product_name} is out of stock."
                )
                cart_item.quantity = cart_item.product.stock
                cart_item.save()

            item_price = cart_item.product.price * cart_item.quantity
            effective_offer = calculate_effective_offer(cart_item.product)
            if effective_offer > 0:
                discount_amount = (effective_offer / Decimal('100.0')) * item_price
                item_price -= discount_amount

            total_dict[cart_item.id] = item_price
            subtotal += item_price

        for cart_item in cart_items:
            cart_item.total_price = total_dict.get(cart_item.id, 0)
            cart_item.save()

        shipping_cost = 10
        total = subtotal + shipping_cost if subtotal else 0

        total_discount = sum(cart_item.coupon.discount_price for cart_item in cart_items if cart_item.coupon)
        total = subtotal - total_discount + shipping_cost

        request.session['cart_subtotal'] = str(subtotal)  
        request.session['cart_total'] = str(total)


        if subtotal >= coupon.minimum_amount:
            messages.success(request, "Coupon applied successfully")
            request.session["discount"] = coupon.discount_price
            total = subtotal - coupon.discount_price + shipping_cost
        else:
            messages.error(request, "Coupon not available for this price")
            total = subtotal + shipping_cost

        for cart_item in cart_items:
            cart_item.total_price = total_dict.get(cart_item.id, 0)
            cart_item.save()
        context = {
            "cart_items": cart_items,
            "subtotal": subtotal,
            "total": total,
            "coupons": coupons,
            "discount_amount": coupon.discount_price,
        }

        return render(request, "main/cart.html", context)

    return redirect("cart")
#============================wallet==============================#
from django.db.models import Sum

def wallet(request):
    if request.user.is_authenticated:
        user = request.user
        customer = get_object_or_404(Customer, email=user.email)
        
        # Calculate total wallet balance
        total_wallet_balance = Wallet.objects.filter(user=customer).aggregate(total=Sum('amount'))['total']
        total_wallet_balance = total_wallet_balance or 0  # Handle None value

        # Calculate total credited and debited amounts
        total_credited_amount = Wallet.objects.filter(user=customer, is_credit=True).aggregate(total=Sum('amount'))['total']
        print(total_credited_amount)
        total_credited_amount = total_credited_amount or 0  # Handle None value
        
        total_debited_amount = Wallet.objects.filter(user=customer, is_credit=False).aggregate(total=Sum('amount'))['total'] or 0
        print(total_debited_amount,'111111111111222')
        # difference  =total_debited_amount or 0  # Handle None value
        total_debited_amount = abs(total_debited_amount)
        print(total_debited_amount)
        # total_wallet_balance = total_credited_amount + total_added_amount - total_debited_amount
        print("Total Debited Amount (Absolute Value):", total_debited_amount)
        wallets = Wallet.objects.filter(user=customer).order_by("-created_at")

        context = {
            "customer": customer,
            "wallets": wallets,
            "total_wallet_balance": total_wallet_balance,
            "total_credited_amount": total_credited_amount,
            "total_debited_amount": total_debited_amount,
        }
        return render(request, "core/wallet.html", context)
    else:
        return redirect("core:home")
    
def razorpay(request, address_id):
    user = request.user
    cart_items = Cart.objects.filter(user=user)
    subtotal = 0
    shipping_cost = 10
    total = subtotal + shipping_cost if subtotal else 0
    subtotal = Decimal(request.session.get('cart_subtotal', 0))
    total = Decimal(request.session.get('cart_total', 0))
    discount = request.session.get("discount", 0)

    if discount:
        total -= discount
   
    payment = "razorpay"
    user = request.user
    cart_items = Cart.objects.filter(user=user)
    address = Address.objects.get(id=address_id)

    order = Order.objects.create(
        user=user,
        address=address,
        amount=total,
        payment_type=payment,
    )

    for cart_item in cart_items:
        product = cart_item.product
        product.stock -= cart_item.quantity
        product.save()

        order_item = OrderItem.objects.create(
            order=order,
            product=cart_item.product,
            quantity=cart_item.quantity,
            image=cart_item.product.image,
        )

    cart_items.delete()
    return redirect("core:success")

@login_required
def proceedtopay(request):
    # if request.method == 'POST':
        # user = request.user
        # address_id = request.POST.get('addressId')
        # payment_type = request.POST.get('payment')
        # print(address_id,'qaaaaaaaaaaaaaaaaaaaaa')
        # print(payment_type,'111111111111111111111111111')


        
        # if not address_id:
        #     messages.error(request, "Please select an address.")
        #     return HttpResponseRedirect(reverse('core:checkout')) 
            
        # if not payment_type:
        #     messages.error(request, "Please select payment method.")
        #     return HttpResponseRedirect(reverse('core:checkout'))
            
    user = request.user 
    cart = Cart.objects.filter(user=request.user)
    subtotal = 0
    discount = 0  # Initialize discount to 0
    
    # Calculate subtotal and apply discounts
    for cart_item in cart:
        product = cart_item.product

        if cart_item.quantity > product.stock:
            messages.error(request, f"Insufficient stock for {product.product_name}.")
            return redirect("core:checkout")
        
        item_price = cart_item.product.get_discounted_price() * cart_item.quantity
        subtotal += item_price
    global_discount = request.session.get("discount", 0)
    discount += global_discount
    shipping= request.session.get('shipping', 0)
    # Calculate total including shipping and discounts
    total = subtotal - discount + shipping
    return JsonResponse({"total": total})

#=================categoryproducts======================================#

def category_products(request, category_id):
    # Retrieve selected filters from the request
    selected_category = request.GET.get('category')
    selected_price_range = request.GET.get('price_range')
    selected_color_range = request.GET.get('color_range')
    # Get the main category object
    main_category = Main_Category.objects.get(pk=category_id)

    # Filter products queryset based on selected filters
    products = Product.objects.filter(main_category=main_category)

    if selected_price_range:
        price_min, price_max = map(int, selected_price_range.split('-'))
        products = products.filter(price__gte=price_min, price__lte=price_max)

    if selected_color_range:
        products = products.filter(color=selected_color_range)

    # Pass the filtered products and main category to the template
    context = {
        'products': products,
        'main_category': main_category,
    }
    return render(request, 'core/products.html', context)
@csrf_exempt
def create_razorpay_order(request):
    if request.method == 'POST':
        # Parse JSON data from the request body
        data = json.loads(request.body)
        amount = data.get('amount')
        
        # Add the amount to the wallet
        if request.user.is_authenticated:
            user = request.user
            customer = get_object_or_404(Customer, email=user.email)
            wallet = Wallet.objects.create(user=customer, amount=amount)
            # You might want to handle payment status here as well
            return JsonResponse({"total": amount})
        else:
            return JsonResponse({'error': 'User not authenticated'}, status=401)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
#===============================home==================================#

def home(request):
    # Retrieve first 10 products ordered by ID
    products = list(Product.objects.filter(deleted=False).order_by('-id')[:10])
    # Retrieve first 10 deals ordered by offer
    deals = list(Product.objects.filter(deleted=False).order_by('-offer')[:12])
    top_products = Product.objects.annotate(total_orders=Count('orderitem_product__order')).order_by('-total_orders')[:5]
    top_deals = Product.objects.filter(deleted=False).order_by('-offer')
    # top_brands = Brand.objects.annotate(total_orders=Count('product__order')).order_by('-total_orders')[:5]
    budget_products = Product.objects.filter(deleted=False).order_by('offer')
    banners = Banner.objects.filter(deleted=False)
    default_main_category = Main_Category.objects.filter(deleted=False)
    # Shuffle the first 10 deals and products separately
    shuffle(products)
    shuffle(deals)

    context = {
        'products': products, 
        'default_main_category': default_main_category,
        'banners': banners,
        'deals': deals,
        'top_products': top_products,
        'top_deals': top_deals,
        # 'top_brands': top_brands,
        'budget_products': budget_products,
    }  
    return render(request, "core/home.html", context)
#===========================genrativevoice===================================#
def generate_invoice(request, order_id):
    order = get_object_or_404(Order, pk=order_id)
    order_items = OrderItem.objects.filter(order=order)

    user_address = Address.objects.filter(user=request.user).first()
    # Calculate total amount
    cart_total_amount = order.amount
    user_first_name = request.user.username
    user_last_name = request.user.last_name

    subtotal = sum(item.product.price * item.quantity for item in order_items)
    total = subtotal 
     
    shipping=request.session.get('shipping','0')
    subtotalsss = request.session.get('subtotal', '0')
    totalss = request.session.get('total', '0')
    context = {
        'order': order,
        'order_items': order_items,
        'cart_total_amount': cart_total_amount,
        'user_address': user_address,  # Add the user's address to the context
        'user_first_name': user_first_name,
        'user_last_name': user_last_name,
        'subtotal': subtotal,
        'subtotalss': subtotalsss,
        'total': total,
        'totals': totalss,
        'shipping': shipping,
    }
    return render(request, 'core/invoice.html', context)

def download_invoice(request, order_id):
    return HttpResponse("This is the invoice content.", content_type='application/pdf')

#=====================shipping location map====================================#

from geopy.geocoders import Nominatim
from geopy import distance
def new(request):
    geocoder = Nominatim(user_agent="nahjas")

    location1 = "kannur"

    # Get the user's address and extract the city from it
    user_address = Address.objects.filter(user=request.user).first()
    if user_address:
        location2 = user_address.city
    else:
        location2="kannur"

    cor1 = geocoder.geocode(location1)
    cor2 = geocoder.geocode(location2)
   
    lat1, long1 = cor1.latitude, cor1.longitude
    lat2, long2 = cor2.latitude, cor2.longitude
    place1 = (lat1, long1)
    place2 = (lat2, long2)
    dist = distance.distance(place1, place2).km
    # Determine shipping amount based on distance
    if dist <= 100:
        shipping_amount = 50
    elif dist <= 200:
        shipping_amount = 100
    else:
        shipping_amount = 200

    city_distance, created = CityDistance.objects.get_or_create(user=request.user, defaults={'distance': 0.0, 'price': 0.0})

    city_distance.distance = dist
    city_distance.save()

    return redirect('core:checkout')
#============================================rewiew==============================#
from .forms import ReviewForm 
@login_required
def add_review(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    
    if request.method == 'POST':
        form = ReviewForm(request.POST)
        if form.is_valid():
            review = form.save(commit=False)
            review.user = request.user
            review.product = product  # Assign the Product instance
            review.save()
            return redirect('core:product_detail', id=product.id)
    else:
        form = ReviewForm()

    return render(request, 'core/product_details.html', {
        'product': product,
        'form': form,
        'reviews': product.review_set.all(),
    })
 

# @login_required
# def send_message(request):
#     if request.method == 'POST':
#         message_text = request.POST.get('message')
#         receiver_id = request.POST.get('receiver_id')
#         receiver = User.objects.get(id=receiver_id)
#         Message.objects.create(sender=request.user, receiver=receiver, message=message_text)
#         return redirect('core:sent_messages')  # Redirect to the sent messages page after sending
#     else:
#         users = User.objects.exclude(id=request.user.id)  # Exclude the current user from the list of users
#         return render(request, 'core/compose_message.html', {'users': users})

# def inbox(request):
#     user = request.user  # Assuming request.user is a User object
#     received_messages = Message.objects.filter(receiver=user)
#     print(received_messages.message)
#     return render(request, 'adminside/inbox.html', {'received_messages': received_messages})

# @login_required
# def sent_messages(request):
#     sent_messages = Message.objects.filter(sender=request.user)
#     return render(request, 'core/sent_messages.html', {'sent_messages': sent_messages})




def csrf_failure(request, reason="aaaaaaaaf csrffffff wdhkdshdsdidhsidwdwdwiww"):
    return render(request, 'core/csrf_failure.html', {'reason': reason})
