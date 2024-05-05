# views.py

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
# from .forms import *
# from .forms import LoginForm 
from core.models import Main_Category ,Product
# from .models import Customer
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
# def home(request):
#     return render(request,'core/home.html')

@never_cache
def home(request):
        user = request.user
        return render(request, "core/home.html",{'user': user})
    
def send_otp(email):
    digits = "0123456789"
    OTP = ""
    for i in range(6):
        OTP += digits[random.randint(0, 9)]

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

    return OTP
               
@never_cache
def signupPage(request):
    if 'email' in request.session:
        return redirect('core:home')

    if request.method == 'POST':
        email     =    request.POST.get('email')
        ph_no    =    request.POST.get('ph_no')
        username  =    request.POST.get('username')
        pass1     =    request.POST.get('password1')
        pass2     =    request.POST.get('password2')
        

        # Check if all fields except username contain only whitespace
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
 
        # message = generate_otp()
        # print(message)
        # sender_email = "aslamthayamkulam@gmail.com"
        # receiver_mail = email
        # password = "qzyrtqxbcrdoqlpm"


        # try:
        #     with smtplib.SMTP("smtp.gmail.com", 587) as server:
        #         server.starttls()
        #         server.login(sender_email, password)
        #         server.sendmail(sender_email, receiver_mail, message)

        # except smtplib.SMTPAuthenticationError:
        #     messages.error(request, 'Failed to send OTP email. Please check your email configuration.')
        #     return redirect('core:signupPage')
        # referral_codes = generate_referral_code()
        user = Customer.objects.create_user(username=username, password=pass1, email=email,ph_no=ph_no)
        user.save()

        # if refferal:
        #     referrer = Customer.objects.get(referral_code = refferal)
        #     if referrer:
        #         referrer.referral_amount += 100
        #         referrer.save()
        email = request.POST.get('email')
        otp=send_otp(email)
        request.session['email'] =  email
        request.session['otp']   =  otp
        messages.success (request, 'OTP is sent to your email')
        
        return redirect('core:verify_otp')

    return render(request, 'core/registration.html')

     # ......... End Signup .............

def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        if entered_otp == request.session.get('otp'):
            # OTP is correct, redirect to home page or wherever needed
            del request.session['otp']
            del request.session['email']
            messages.success(request, "Signup successful! You can now log in.")
            return redirect('core:loginPage')
        else:
            # Incorrect OTP, handle accordingly
            messages.error(request, "Incorrect OTP, please try again.")
    return render(request, "core/otp_user.html")


# def loginPage(request):
#     if request.method == 'POST':
#         email = request.POST.get('email')
#         password = request.POST.get('password')
        
#         print("Email:", email)  # Debugging statement
#         print("Password:", password)  # Debugging statement
        
#         # Use authenticate() method to verify credentials
#         user = authenticate(request, email=email, password=password)
        
#         print("Authenticated User:", user)  # Debugging statement
        
#         if user is not None:
#             # Use login() method to log in the user
#             login(request, user)
#             messages.success(request, "Login successful. Welcome back!")
#             return redirect('core:home')
#         else:
#             messages.error(request, "Username or password is incorrect")
#             return render(request, 'core/userlogin.html')
#     else:
#         return render(request, 'core/userlogin.html')

@never_cache


def loginPage(request):
    context = {
        'messages': messages.get_messages(request)
    }
    if 'email' in request.session:
        return redirect('core:home')

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

def generate_otp(length = 6):
    return ''.join(secrets.choice("0123456789") for i in range(length)) 


def validate_email(email):
    return '@' in email and '.' in email

def custom_logout(request):
    print(request.user)
    logout(request)
    return redirect('core:home')



def google(request):

      context = {
        'provider': 'Google'  # You can dynamically determine the provider here
     }
      return render(request,'core/google.html',context)






# categories user side=================================================================

def user_category_view(request):
    print(request.user)
    categories = Main_Category.objects.filter(deleted=False)  # Fetch active categories
    return render(request, 'core/user_categories.html', {'categories': categories})




# product user side =====================================================================


def products(request):
     products = Product.objects.filter(deleted=False).order_by('-id')
     return render(request, 'core/products.html', {'products': products})

# productshowing page======================================================================

def product_detail(request, id):
    # Get the product and its variants
    product = get_object_or_404(Product, id=id)
    discounted_price = product.get_discounted_price()
    
    
    # Fetch additional images from the related ProductImage model
    additional_images = product.additional_images.all()


    # Fetch similar products based on the main category
    similar_products = Product.objects.filter(
        main_category=product.main_category  # Filter similar products by main category
    ).exclude(id=product.id).order_by('?')  # Exclude the current product and randomize the order
    
    context = {
        "product": product,
        "additional_images": additional_images,
        "similar_products": similar_products,
        "discounted_price": discounted_price,
    }
    return render(request, "core/product_details.html", context)



#user profile details===================================================================================================



def profile(request):
    if request.user:
        return render(request, 'core/profile_user.html')





@login_required
def manage_profile(request):
    if request.method == 'POST':
        # Get user object
        user = request.user

        # Get user input
        username = request.POST.get('username')
        email = request.POST.get('email')
        phone = request.POST.get('phone')

        # Check for empty fields
        if not ( username and email and phone):
            messages.error(request, 'Please fill in all the required fields.')
            return redirect(reverse('core:manage_profile'))
        
        # Validate phone number
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

    return render(request, 'core/profile_manage.html', {'user': request.user})




phone_validator = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',  # Customize the regex pattern as needed
    message='Enter a valid phone number.',
)



#addresss details=======================================================


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
        return redirect('core:address')
    print(';;;;;;;;;;;;after')
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
    data.delete()  
    return redirect('core:address')



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





@login_required(login_url='core:loginPage') 
def cart(request):
    if "discount" in request.session:
        del request.session["discount"]
    if isinstance(request.user, AnonymousUser):
        device_id = request.COOKIES.get("device_id")
        cart_items = Cart.objects.filter(device=device_id).order_by("id")
    else:
        user = request.user
        cart_items = Cart.objects.filter(user=user).order_by("id")
        
    if request.method == "POST":
        coupon_code = request.POST.get("coupon_code")

        # try:
        #     coupon = Coupon.objects.get(coupon_code=coupon_code, expired=False)
        # except Coupon.DoesNotExist:
        #     messages.error(request, "Invalid or expired coupon code")
        #     return redirect("cart")

        for cart_item in cart_items:
           
            cart_item.save()

        messages.success(request, "Coupon applied successfully")

    subtotal = 0
    total_dict = {}

    for cart_item in cart_items:
        if cart_item.quantity > cart_item.product.stock:
            messages.warning(
                request, f"{cart_item.product} this is out of stock."
            )
            cart_item.quantity = cart_item.product.stock
            cart_item.save()

        # item_price = cart_item.product.price * cart_item.quantity
        # effective_offer = calculate_effective_offer(cart_item.product)
        # if effective_offer > 0:
        #     discount_amount = (effective_offer / Decimal('100.0')) * item_price
        #     item_price -= discount_amount

        # total_dict[cart_item.id] = item_price
        # subtotal += item_price
        cart_item.total_price = cart_item.quantity * cart_item.product.get_discounted_price()
        cart_item.save()
        subtotal += cart_item.total_price


    # for cart_item in cart_items:
    #    subtotal += cart_item.sub_total
       

    shipping_cost = 10
    total = subtotal + shipping_cost if subtotal else 0
    total_without_coupon_discount = subtotal + shipping_cost 

# Update total
    total = total_without_coupon_discount 
    request.session['cart_subtotal'] = str(subtotal)  
    request.session['cart_total'] = str(total)
    # request.session['user'] = user
    # request.session['email'] = request.email
    # print(request.email,"kkkkkkkkkkkeeeeeeeee")

    # coupons = Coupon.objects.all()

    context = {
        "cart_items": cart_items,
        "subtotal": subtotal,
        "total": total,
        # "coupons": coupons,
    }
    return render(request, "core/cart.html", context)





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

    # try:
    #     wishlist_item = Wishlist.objects.get(product=product, user=request.user)
    #     wishlist_item.delete()
    # except Wishlist.DoesNotExist:
    #     pass  

    return redirect('core:cart')






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



@login_required
def remove_from_cart(request, cart_item_id):
        try:
            cart_item = Cart.objects.get(id=cart_item_id, user=request.user)
            cart_item.delete()

        except Cart.DoesNotExist:
            print("Cart doesn't Exist!")
        
        return redirect('core:cart')



#favuraite all ==================================

@login_required(login_url='login') 
def wishlist(request):
    user = request.user
    if isinstance(user, AnonymousUser):
        return redirect('login')  
    else:
        wishlist_items = Wishlist.objects.filter(user=user)
        wishlist_count = wishlist_items.count()

    context = {
        'wishlist_items': wishlist_items,
        'wishlist_count': wishlist_count,
    }

    return render(request, 'core/wishlist.html', context)





def wishlist_count(request):
    user = request.user
    wishlist_items = Wishlist.objects.filter(user=user)
    wishlist_count = wishlist_items.count()

    return JsonResponse({'wishlist_count': wishlist_count})

def add_to_wishlist(request, product_id):
    try:
        product = Product.objects.get(id=product_id)
    except Product.DoesNotExist:
        return redirect('product_not_found')
    user = request.user
    if isinstance(user, AnonymousUser):
            return redirect('login')
    else:
        wishlist, created = Wishlist.objects.get_or_create(product=product, user=user)
    wishlist.save()

    return redirect('core:wishlist')


@login_required(login_url='login')
def remove_from_wishlist(request, wishlist_item_id):
    wishlist_item = get_object_or_404(Wishlist, id=wishlist_item_id, user=request.user)
    wishlist_item.delete()
    return redirect('core:wishlist')

#order manag==================================================================


@never_cache
# @cache_control(no_cache=True, must_revalidate=True, no_store=True)
def checkout(request):
        print('////////////////////////')
    # if 'email' in request.session:
    #     print('email found in session')
    #     email = request.session['email']
    #     print('Email:', email)
        user = request.user
    #     print('User:', user)
        cart_items = Cart.objects.filter(user=user)
        subtotal = 0

        for cart_item in cart_items:
            if cart_item.quantity > cart_item.product.stock:
                messages.warning(
                    request, f"{cart_item.product.product_name} is out of stock."
                )
                print("hhhhhh")
                cart_item.quantity = cart_item.product.stock
                cart_item.save()
                return redirect('core:cart')

        

        for cart_item in cart_items:
            if cart_item.product:
                itemprice2 = (cart_item.product.price ) * (cart_item.quantity)
                subtotal += itemprice2  
            else:
                itemprice2 = (cart_item.product.price) * (cart_item.quantity)
                subtotal += itemprice2  

        shipping_cost = 10 
        discount = request.session.get('discount', 0)
        if discount:
            total = subtotal + shipping_cost - discount if subtotal else 0
            print(discount,"dddddddissssssss")
        else:
            total = subtotal + shipping_cost  if subtotal else 0
        
        subtotal = Decimal(request.session.get('cart_subtotal', 0))
        total = Decimal(request.session.get('cart_total', 0)) - discount
        print(subtotal)
        print(total)
        request.session['subtotal'] = str(subtotal)
        request.session['total'] = str(total)

        user_addresses = Address.objects.filter(user=request.user)

        context = {
            'cart_items': cart_items,
            'subtotal': subtotal,
            'total': total,
            'user_addresses': user_addresses,
            'discount_amount': discount,
            'itemprice': itemprice2  
        }
        return render(request, 'core/checkout.html', context)
    # else:
    #      return redirect('core:signupPage')

@login_required
def place_order(request):
    if request.method == 'POST':
        user = request.user
        address_id = request.POST.get('addressId')
        payment_type = request.POST.get('payment')  

        # Check if address is selected
        if not address_id:
            messages.error(request, "Please select an address.")
            return HttpResponseRedirect(reverse('core:checkout')) 
        
        if not payment_type:
            messages.error(request, "Please select payment method.")
            return HttpResponseRedirect(reverse('core:checkout'))

        cart_items = Cart.objects.filter(user=user, quantity__gt=0)
        in_stock_items = []
        out_of_stock_items = []

        for cart_item in cart_items:
            if cart_item.quantity <= cart_item.product.stock:
                in_stock_items.append(cart_item)
            else:
                out_of_stock_items.append(cart_item)

        # If any item is out of stock, return to checkout page
        if out_of_stock_items:
            messages.warning(request, "Some items are out of stock. Please remove them from your cart.")
            return HttpResponseRedirect(reverse('core:cart'))

        total_offer_price = 0
        total_price = 0
        total_quantity = 0
        for cart_item in in_stock_items:
            # Create order objects within the loop
            order = Order.objects.create(
                user=user,
                address_id=address_id,
                product=cart_item.product,
                amount=cart_item.product.price,
                payment_type=payment_type, 
                status='pending',
                quantity=cart_item.quantity,
            )
       
            total_offer_price += cart_item.product.price
            total_price += cart_item.product.price * cart_item.quantity
            total_quantity += cart_item.quantity

            cart_item.product.stock -= cart_item.quantity
            cart_item.product.save()
            cart_item.delete()

            # You can move this code block here if you want to create order items for each cart item
            OrderItem.objects.create(
                order=order,
                product=cart_item.product,
                quantity=cart_item.quantity,
                image=cart_item.product.image,  # Use cart item's product's image
            )

        return redirect("core:success")




def success(request):
    orders = Order.objects.order_by("-id")[:1]
    context = {
        "orders": orders,
    }
    return render(request, "core/placeorder.html", context)


def order_details(request, id):
    product = get_object_or_404(Order, id=id)
    context = {
        'product' : product
    }
    return render(request, "core/order_details.html", context)
def customer_order(request):
    # if "email" in request.session:
        # user = request.user
        user_orders= Order.objects.all().order_by('-id')

        # Accumulate all order items for all orders
        # all_order_items = []
        # for order in orders:
        #     order_items = order.order_items.all()
        #     all_order_items.extend(order_items)
 
        # context = {
        #     "orders": orders,
        #     "all_order_items": all_order_items,  # Pass all_order_items to the template context
        # }
        return render(request, "core/customer_order.html", {'orders': user_orders})

    # else:
    #     return redirect("core:home")

@login_required
def cancel(request, order_id):
    if request.method == 'POST':
        # Get the order object based on the order_id
        order = get_object_or_404(Order, pk=order_id)

        # Check if the status should be changed to Cancelled
        if order.status in ['pending', 'processing', 'shipped']:
            order.status = 'cancelled'
        else:
            order.status = 'returned'

        variant = order.product
        variant.stock += order.quantity
        variant.save()
        # Return amount to user's wallet
        user = request.user
        # try:
        #     # Retrieve user's wallet
        #     wallet = Wallet.objects.get(user=user)
        # except Wallet.DoesNotExist:
            # If wallet doesn't exist, create one for the user
        wallet = Wallet.objects.create(user=user)

        # Add the amount of cancelled order to the wallet balance if order via razorpay
        if order.payment_type == 'razorpay' or order.payment_type == 'wallet':
            wallet.balance += Decimal(order.amount)
            wallet.save()

        order.save()  # Save the updated status

        # Redirect to the same page or any desired page after status change
        return redirect('core:customer_order')  # Assuming you have a URL named 'orders' defined in your urls.py file
    else:
        # Handle GET requests appropriately, if needed
        # For now, let's redirect to the 'orders' page
        return redirect('core:customer_order')


def cancel_success(request):
    print("successsssssssssssssssssss")
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



@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def order(request):
    user = request.user
    
      
    orders = Order.objects.all().order_by("-id")

    paginator = Paginator(orders, per_page=15)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    context = {
        "orders": page_obj,
        'user':user
    }
    return render(request, "adminside/orders.html", context)
    # else:
        # return redirect("adminside:dashboard")




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
        # total_amount = sum(order_item.product.price * order_item.quantity for order_item in order_items)

        # wallet = Wallet.objects.create(
        #     user=order.user,
        #     order=order,
        #     amount=total_amount,
        #     status="Credited",
        #     created_at=timezone.now(),
        # )
        # wallet.save()

        for order_item in order_items:
            product = order_item.product
            product.stock += order_item.quantity
            product.save()

            order.user.wallet_bal += order_item.product.price * order_item.quantity
            order.user.save()


def return_order(request, order_id, order_item_id):
    user = request.user
    usercustm = Customer.objects.get(email=user)
    try:
        order = Order.objects.get(id=order_id)
        order_item = OrderItem.objects.get(id=order_item_id, order=order)
    except Order.DoesNotExist or OrderItem.DoesNotExist:
        return render(request, 'order_not_found.html')

    # if order.status in ["completed", "delivered"]:
    #     wallet = Wallet.objects.create(
    #         user=user,
    #         order=order,
    #         amount=order_item.product.price * order_item.quantity,
    #         status="Credited",
    #     )
    #     wallet.save()
    product = order_item.product
    product.stock += order_item.quantity
    product.save()
    usercustm.wallet_bal += order_item.product.price * order_item.quantity
    usercustm.save()
    order_item.delete()
    if order.order_items.count() == 0:
        order.status = "Return successful"
        order.save()

    return redirect("core:order_details", order_id=order_id)




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



def product_search(request):
    if request.method == "POST":
        searched = request.POST.get('searched')

        # Split the searched term into individual words
        search_terms = searched.split()

        # Initialize an empty Q object to build the query dynamically
        q_objects = Q()

        # Iterate through each search term and construct the query
        for term in search_terms:
            q_objects |= Q(model__icontains=term) | Q(color__icontains=term)

        # Filter products based on the constructed query
        products = Product.objects.filter(q_objects).distinct()

        context = {
            'products': products,
        }
        return render(request, 'core/products.html', context)

    return redirect('core:home')


