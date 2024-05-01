from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from core.models import Main_Category , Product, ProductImage
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from core.models import Customer
from django.contrib.auth import logout


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
def dashboard(request):
    # Set session data
    request.session['user_id'] = request.user.id
    request.session['username'] = request.user.username
    return render(request,'adminside/dashboard.html')


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
        offer = request.POST.get('offer')
        image = request.FILES.get('image')
        delete = request.POST.get('delete', False) == 'True'
        
        # Validate input
        if not main_category_name.strip():
            messages.error(request, "Main category name cannot be empty.")
            return redirect('adminside:add_categories')
        if not description.strip():
            messages.error(request, "Description cannot be empty.")
            return redirect('adminside:add_categories')
        if not offer:
            messages.error(request, "Offer cannot be empty.")
            return redirect('adminside:add_categories')
        try:
            offer = float(offer)
            if offer < 0:
                raise ValidationError("Offer must be a positive number.")
        except ValueError:
            messages.error(request, "Offer must be a valid number.")
            return redirect('adminside:add_categories')
        if not image:
            messages.error(request, "Please upload an image.")
            return redirect('adminside:add_categories')
            
        # Check if the category name already exists
        if Main_Category.objects.filter(name=main_category_name).exists():
            messages.error(request, "Category already exists.")
            return redirect('adminside:add_categories')
            
        # Save data to the database
        main_category = Main_Category(
            name=main_category_name,
            descriptions=description,
            offer=offer,
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
        offer              = request.POST['offer']

        # Retrieve existing data
        edit = Main_Category.objects.get(id=id)

        # Update fields
        if Main_Category.objects.filter(name = main_category_name).exclude(id=id).exists():
            messages.error(request, "Category is already exists.")
            return render(request,'adminside/update_main_categories.html',{"data": data})

            
        edit.name = main_category_name
        edit.descriptions = description 
        edit.offer = offer

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
    items = Product.objects.all().order_by('-id')
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

