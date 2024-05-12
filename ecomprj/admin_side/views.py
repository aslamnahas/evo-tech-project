from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from core.models import Main_Category , Product, ProductImage  , Wishlist
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from core.models import Customer ,Order,OrderItem 
from django.contrib.auth import logout
from django.core.paginator import Paginator
import json
import io
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_control,never_cache
# from category.models import Category
from django.shortcuts import render,redirect
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_control,never_cache
# from .models import Customer,Address
from django.core.exceptions import ValidationError
from django.contrib import messages,auth
import secrets
from django.contrib.auth import authenticate
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
import smtplib
import json
from django.utils import timezone
from django.db.models import Sum, F, FloatField, DateField
from django.db.models.functions import Cast
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.core.paginator import Paginator
from django.core.exceptions import ObjectDoesNotExist
import string,random
from django.contrib import messages
from django.urls import reverse
from django.core.validators import RegexValidator
from django.shortcuts import render
from datetime import datetime
from django.http import HttpResponse
from django.contrib import messages
from django.http import FileResponse
import io
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
# from products.models import OrderItem
from reportlab.platypus import SimpleDocTemplate


from django.core.serializers.json import DjangoJSONEncoder
from decimal import Decimal

class DecimalEncoder(DjangoJSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)  # Convert Decimal to string
        return super().default(obj)
    


from django.db.models import Sum, F, FloatField
from django.utils import timezone

from django.http import JsonResponse
from django.db.models.functions import TruncMonth, TruncYear
from django.views.decorators.cache import never_cache
from django.http.request import HttpHeaders
from datetime import date


def admin_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            # Redirect to dashboard upon successful login
            return redirect('adminside:dashboard')  # Assuming 'dashboard' is the name of the URL pattern for the dashboard
        else:
            # Handle invalid login credentials
            messages.error(request, 'Invalid username or password.')
    # Render the login form
    return render(request, 'adminside/adminlogin.html')

# def users(request):

#     return render(request,'adminside/users.html')

# @login_required
# def dashboard(request):
#     # Set session data
#     request.session['user_id'] = request.user.id
#     request.session['username'] = request.user.username
#     return render(request,'adminside/dashboard.html')


def users(request):
     users = Customer.objects.all()
     context = {
            'users':users,
        }
     return render(request,'adminside/users.html',context)


def user_block(request, user_id):
    user = get_object_or_404(Customer, id=user_id)
    user.is_blocked = not user.is_blocked  # Toggle the block status
    user.save()

    if user.is_blocked:
        logout(request)
    return redirect('adminside:users')

def main_category(request):
    data = Main_Category.objects.all().order_by('id')
    return render(request, "adminside/categories.html", {"data": data})


def add_main_category(request):
    if request.method == 'POST':
        main_category_name = request.POST.get('main_category_name')
        description = request.POST.get('description')
        # offer = request.POST.get('offer')
        image = request.FILES.get('image')
        delete = request.POST.get('delete', False) == 'True'
        
        # Validate input
        if not main_category_name.strip():
            messages.error(request, "Main category name cannot be empty.")
            return redirect('adminside:add_categories')
        if not description.strip():
            messages.error(request, "Description cannot be empty.")
            return redirect('adminside:add_categories')
        # if not offer:
        #     messages.error(request, "Offer cannot be empty.")
        #     return redirect('adminside:add_categories')
        # try:
        #     offer = float(offer)
        #     if offer < 0:
        #         raise ValidationError("Offer must be a positive number.")
        # except ValueError:
        #     messages.error(request, "Offer must be a valid number.")
        #     return redirect('adminside:add_categories')
        # if not image:
        #     messages.error(request, "Please upload an image.")
        #     return redirect('adminside:add_categories')
            
        # Check if the category name already exists
        if Main_Category.objects.filter(name=main_category_name).exists():
            messages.error(request, "Category already exists.")
            return redirect('adminside:add_main_category')
            
        # Save data to the database
        main_category = Main_Category(
            name=main_category_name,
            descriptions=description,
            # offer=offer,
            img=image,
            deleted=delete
        )
        main_category.save()
        messages.success(request, "Category added successfully.")
        return redirect('adminside:categories')
        
    return render(request, 'adminside/add_categories.html')


#update_categories

def update_main_category(request, id):
    data = Main_Category.objects.get(id=id)

    if request.method      == 'POST':
        main_category_name = request.POST['main_category_name']
        description        = request.POST['description']
        # offer              = request.POST['offer']

        # Retrieve existing data
        edit = Main_Category.objects.get(id=id)

        # Update fields
        if Main_Category.objects.filter(name = main_category_name).exclude(id=id).exists():
            messages.error(request, "Category is already exists.")
            return render(request,'adminside/update_main_categories.html',{"data": data})

            
        edit.name = main_category_name
        edit.descriptions = description 
        # edit.offer = offer

        if 'image' in request.FILES:
            image = request.FILES['image']
            edit.img = image
        
        # Save updated data
        edit.save()

        return redirect('adminside:categories')

    return render(request,'adminside/update_main_categories.html',{"data": data})







def soft_delete_category(request, id):
    data = Main_Category.objects.get(id=id)

    data.deleted = not data.deleted
    data.save()

    return redirect('adminside:categories')



#delete categories



def delete_main_category(request,id):
    data = Main_Category.objects.get(id=id) 
    data.delete()  
    return redirect('adminside:categories')






# product============================================================================================================
                                # add --- update ---- delete ---soft delete--

def products(request):
    items_list = Product.objects.all().order_by('-id')
    paginator = Paginator(items_list, 10)  # Show 10 items per page

    page_number = request.GET.get('page')
    items = paginator.get_page(page_number)

    return render(request, 'adminside/products.html', {"items": items})

def add_product(request):
    data = Main_Category.objects.all()

    if request.method == 'POST':
        try:
            # Extract data from the POST request
            model = request.POST['model']
            description = request.POST['description']
            color = request.POST['color']
            display_size = request.POST['display_size']
            camera = request.POST.get('camera', '')  # Get camera data or empty string if not provided
            battery = request.POST.get('battery', '')  # Get battery data or empty string if not provided
            network = request.POST.get('network', False) == 'true'
            price = request.POST.get('price')
            offer = request.POST.get('offer')
            stock = request.POST.get('stock')
            main_category_id = request.POST.get('main_category_id')

            # Retrieve the main category object
            main_cat = get_object_or_404(Main_Category, id=main_category_id)

            # Create a new Product object
            new_product = Product.objects.create(
                main_category=main_cat,
                model=model,
                description=description,
                color=color,
                display_size=display_size,
                camera=camera,
                battery=battery,
                network=network,
                price=price,
                offer=offer,
                stock=stock,
                image=request.FILES.get('image')
            )

            # Create ProductImage objects for additional images
            images = request.FILES.getlist('images')
            for img in images:
                ProductImage.objects.create(product=new_product, image=img)

            messages.success(request, 'Product added successfully.')
            return redirect('adminside:products')

        except Exception as e:
            messages.error(request, f'Error occurred: {str(e)}')

    return render(request, 'adminside/add_product.html', {'data': data})




#update product==================================================================================

def update_product(request, id):
    data = Main_Category.objects.all()
  
    product = Product.objects.get(id=id)

    if request.method == 'POST':
        model = request.POST['model']
        description = request.POST['description']
        color = request.POST['color']
        display_size = request.POST['display_size']
        camera = request.POST.get('camera', '')  # Get camera with default empty string
        network = request.POST.get('network', False)
        price = request.POST.get('price')
        battery = request.POST.get('battery', '')  # Get battery with default empty string
        images = request.FILES.getlist('images')
        offer  = request.POST['offer']
        stock = request.POST.get('stock') 
        # brand_id = request.POST.get('brand')
        main_cat_id = request.POST.get('phone_category')

        main_cat = Main_Category.objects.get(id=main_cat_id)

        # Retrieve existing data
        edit = Product.objects.get(id=id)

        # Update data in the table

        edit.main_category = main_cat  
        edit.model = model
        edit.description = description
        edit.color = color
        edit.display_size = display_size
        edit.camera = camera if camera else None  # Set to None if camera is empty
        edit.network = network
        edit.price = price
        edit.offer = offer
        edit.stock = stock
        edit.battery = battery if battery else None  # Set to None if battery is empty

        # Update main image only if the user provided
        if 'image' in request.FILES:
            image = request.FILES['image']
            edit.image = image

        edit.save()

        # Remove existing images associated with the product
        existing_images = ProductImage.objects.filter(product=edit)
        for existing_image in existing_images:
            existing_image.delete()

        # Save multiple new images associated with the product
        for img in images:
            ProductImage.objects.create(product=edit, image=img)

        return redirect('adminside:products')

    context = {
        'product': product,
        'data': data,
        
    }

    return render(request, "adminside/update_product.html", context)


# soft delete product====================================================================================




def soft_delete_product(request, id):
    data = get_object_or_404(Product, id=id)

    data.deleted = not data.deleted
    data.save()

    return redirect('adminside:products')




@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def dashboard(request):
    orders = Order.objects.order_by("-id")
    labels = []
    data = []
    for order in orders:
        labels.append(str(order.id))
        data.append(float(order.amount))  # Convert Decimal to float

    total_customers = Customer.objects.count()
    # print(total_customers)

    # Calculate the count of new users in the last one week
    one_week_ago = timezone.now() - timezone.timedelta(weeks=1)
    new_users_last_week = Customer.objects.filter(date_joined__gte=one_week_ago).count()

    # Get the total number of orders
    total_orders = Order.objects.count()

    # Calculate the count of orders in the last one week
    orders_last_week = Order.objects.filter(date__gte=one_week_ago).count()

    # Calculate the total amount received
    total_amount_received = Order.objects.aggregate(
        total_amount_received=Cast(Sum(F('amount')), FloatField())
    )['total_amount_received'] or 0

    # Calculate the total amount received in the last week
    total_amount_received_last_week = Order.objects.filter(date__gte=one_week_ago).aggregate(
        total_amount_received=Cast(Sum(F('amount')), FloatField())
    )['total_amount_received'] or 0
    print(total_amount_received_last_week)


    categories = Main_Category.objects.annotate(num_products=Count('product'))
    category_labels = [category.name for category in categories]
    category_data = [category.num_products for category in categories]

    total_products = Product.objects.count()

    time_interval = request.GET.get('time_interval', 'all')  # Default to 'all' if not provided
    if time_interval == 'yearly':
        orders = Order.objects.annotate(date_truncated=TruncYear('date', output_field=DateField()))
        orders = orders.values('date_truncated').annotate(total_amount=Sum('amount'))
    elif time_interval == 'monthly':
        orders = Order.objects.annotate(date_truncated=TruncMonth('date', output_field=DateField()))
        orders = orders.values('date_truncated').annotate(total_amount=Sum('amount'))
    else:
        # Default to 'all' or handle other time intervals as needed
        orders = Order.objects.annotate(date_truncated=F('date'))
        orders = orders.values('date_truncated').annotate(total_amount=Sum('amount'))

    # Calculate monthly sales
    monthly_sales = Order.objects.annotate(
        month=TruncMonth('date')
    ).values('month').annotate(total_amount=Sum('amount')).order_by('month')
    print(monthly_sales)
    # Extract data for the monthly sales chart
    monthly_labels = [entry['month'].strftime('%B %Y') for entry in monthly_sales]
    monthly_data = [float(entry['total_amount']) for entry in monthly_sales]
    print(monthly_data)

    # Add this block to handle AJAX request for filtered data
    headers = HttpHeaders(request.headers)
    is_ajax_request = headers.get('X-Requested-With') == 'XMLHttpRequest'

    if is_ajax_request and request.method == 'GET':
        time_interval = request.GET.get('time_interval', 'all')
        filtered_labels = []
        filtered_data = []

        if time_interval == 'yearly':
            filtered_orders = Order.objects.annotate(
                date_truncated=TruncYear('date', output_field=DateField())
            )
        elif time_interval == 'monthly':
            filtered_orders = Order.objects.annotate(
                date_truncated=TruncMonth('date', output_field=DateField())
            )
        else:
            # Default to 'all' or handle other time intervals as needed
            filtered_orders = Order.objects.annotate(date_truncated=F('date'))

        filtered_orders = filtered_orders.values('date_truncated').annotate(total_amount=Sum('amount')).order_by('date_truncated')
        print(filtered_orders)
        filtered_labels = [entry['date_truncated'].strftime('%B %Y') for entry in filtered_orders]
        filtered_data = [float(entry['total_amount']) for entry in filtered_orders]
        print( filtered_data )

        return JsonResponse({"labels": filtered_labels, "data": filtered_data})
    context = {
        "labels": json.dumps(labels),
        "data": json.dumps(data),
        "total_customers": total_customers,
        "new_users_last_week": new_users_last_week,
        "total_orders": total_orders,
        "orders_last_week": orders_last_week,
        "total_amount_received": total_amount_received,
        "total_amount_received": total_amount_received_last_week,
        "total_products": total_products,
        "category_labels": json.dumps(category_labels),
        "category_data": json.dumps(category_data),
    }
    context.update({
        "monthly_labels": json.dumps(monthly_labels),
        "monthly_data": json.dumps(monthly_data),
    })

    # if "admin" in request.session:
    return render(request, "adminside/home.html", context)
    # else:
    #     return redirect("adminside:home")
    

    
from django.http import JsonResponse
from django.db.models import Sum
from django.db.models.functions import TruncMonth, TruncYear, Cast
from django.db.models.functions import TruncDate
from django.views.decorators.http import require_GET

@require_GET
def filter_sales(request):
    time_interval = request.GET.get('time_interval', 'all')

    if time_interval == 'yearly':
        # Filter data for yearly sales
        filtered_data = Order.objects.annotate(
            date_truncated=TruncYear('date')
        ).values('date_truncated').annotate(total_amount=Sum('amount')).order_by('date_truncated')

    elif time_interval == 'monthly':
        # Filter data for monthly sales
        filtered_data = Order.objects.annotate(
            date_truncated=TruncMonth('date')
        ).values('date_truncated').annotate(total_amount=Sum('amount')).order_by('date_truncated')

    else:
        # Default to 'all' or handle other time intervals as needed
        # Here, we are using DateTrunc to truncate the date to a day
        filtered_data = Order.objects.annotate(
            date_truncated=TruncDate('day', 'date')
        ).values('date_truncated').annotate(total_amount=Sum('amount')).order_by('date_truncated')

    # Extract data for the filtered chart
    filtered_labels = [entry['date_truncated'].strftime('%B %Y') for entry in filtered_data]
    filtered_data = [float(entry['total_amount']) for entry in filtered_data]

    return JsonResponse({"labels": filtered_labels, "data": filtered_data})









def report_generator(request, orders):
    from_date_str = request.POST.get('from_date')
    to_date_str = request.POST.get('to_date')

    from_date = datetime.strptime(from_date_str, '%Y-%m-%d').date()
    to_date = datetime.strptime(to_date_str, '%Y-%m-%d').date()

    if from_date > date.today() or to_date > date.today():
            # Return an error response or show a message
            return HttpResponse('Please enter a valid date.')
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    story = []

    data = [["Order ID", "Total Quantity", "Product IDs", "Product Names", "Amount"]]

    total_sales_amount = 0  # Initialize total sales amount sum

    for order in orders:
        # Retrieve order items associated with the current order
        order_items = OrderItem.objects.filter(order=order)
        total_quantity = sum(item.quantity for item in order_items)

        if order_items.exists():
            product_ids = ", ".join([str(item.product.id) for item in order_items])
            product_names = ", ".join([str(item.product.model) for item in order_items])
        else:
            product_ids = "N/A"
            product_names = "N/A"

        order_amount = order.amount
        total_sales_amount += order_amount  # Accumulate total sales amount

        data.append([order.id, total_quantity, product_ids, product_names, order_amount])

    # Add a row for the total sales amount at the end of the table
    data.append(["Total Sales", "", "", "", total_sales_amount])

    # Create a table with the data
    table = Table(data, colWidths=[1 * inch, 1.5 * inch, 2 * inch, 3 * inch, 1 * inch])

    # Style the table
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.gray),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, -1), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ])
    table.setStyle(table_style)

    # Add the table to the story and build the document
    story.append(table)
    doc.build(story)

    buf.seek(0)
    return FileResponse(buf, as_attachment=True, filename='orders_report.pdf')





def report_pdf_order(request):
    if request.method == 'POST':
        from_date = request.POST.get('from_date')
        to_date = request.POST.get('to_date')
        try:
            from_date = datetime.strptime(from_date, '%Y-%m-%d').date()
            to_date = datetime.strptime(to_date, '%Y-%m-%d').date()
        except ValueError:
            return HttpResponse('Invalid date format.')
        orders = Order.objects.filter(date__range=[from_date, to_date]).order_by('-id')
        return report_generator(request, orders)
    
    

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def home(request):
    user_id = None  # Default value when the user is not authenticated

    if request.user.is_authenticated:
        user_id = request.user.id

    categories = Main_Category.objects.all()
    # banners = Banner.objects.all()
    wishlist = Wishlist.objects.all()

    for category in categories:
        category.product_count = category.product_set.count()


    # Get the first 10 products (you may need to adjust the sorting logic as needed)
    products = Product.objects.filter(is_listed=True).order_by('-id')[:10]

    mobile_category = Main_Category.objects.get(name='phone')
    products_mobile = Product.objects.filter(main_category=mobile_category, is_listed=True).order_by('-id')[:10]

    context = {
        'categories': categories,
        # 'banners': banners,
        'wishlist': wishlist,
        'user_id': user_id,
        'products': products,
        'products_mobile': products_mobile,
    }

    return render(request, 'adminside/home.html', context)

   