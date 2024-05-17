from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin,Group,Permission
from django.db import models
from django.utils import timezone
from datetime import date
from decimal import Decimal
from django.db import models
from django.contrib.auth.models import AbstractUser
from .manager import CustomUserManager
from django.utils import timezone
# from products.models import Order
# Create your models here.

class Customer(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    username = models.CharField(max_length=30, blank=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    ph_no = models.CharField(max_length=15, blank=False, null=True)
    wallet_bal = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    rafferal_code = models.CharField(max_length=100, null=False)
    is_blocked = models.BooleanField(default=False) 
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    # Specify unique related names for groups and user_permissions
    groups = models.ManyToManyField(Group, related_name='custom_user_set')
    user_permissions = models.ManyToManyField(Permission, related_name='custom_user_set')

    def __str__(self):
        return self.email
    
    class Meta:
        ordering = ['-id']
    
       

# #category--------------------------------------------------

class Main_Category(models.Model):
    name = models.CharField(max_length=100)
    descriptions = models.TextField(default='Default Description')
    offer = models.PositiveIntegerField(default=0, null=True, blank=True)
    img = models.ImageField(upload_to='categories', default='null', null=True, blank=True)
    deleted = models.BooleanField(default=False)
    objects = models.Manager()

    def __str__(self):
        return str(self.name)
    


# product====================================================================



class Product(models.Model):
    main_category = models.ForeignKey(Main_Category, on_delete=models.CASCADE)
    # brand = models.ForeignKey(Brand, on_delete=models.CASCADE)
    model = models.CharField(max_length=100)
    description = models.TextField()
    color = models.CharField(max_length=10)
    display_size = models.IntegerField()
    camera = models.CharField(max_length=20, null=True, blank=True)
    network = models.BooleanField()
    price = models.IntegerField(default=0) 
    offer = models.PositiveIntegerField(default=0, null=True, blank=True)
    battery = models.IntegerField(null=True, blank=True)
    stock = models.IntegerField(default=0)  # Add the stock field 
    image = models.ImageField(upload_to='products',
                              default='default_image.jpg')
    deleted = models.BooleanField(default=False)
    objects = models.Manager()
    is_listed = models.BooleanField(default=True)
   

    def __str__(self):
        return self.model
    
    def get_discounted_price(self):
        if self.offer:
            discounted_price = self.price - (self.price * self.offer / 100)
            return discounted_price
        else:
            return self.price
    


class ProductImage(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='additional_images')
    image = models.ImageField(upload_to='product_images', blank=True, null=True)
    objects = models.Manager()
    def __str__(self):
        return f"Image for {self.product.model}"

    def toggle_deleted(self):
        self.deleted = not self.deleted
        self.save()







class Address(models.Model):
    user              = models.ForeignKey(Customer,on_delete=models.CASCADE)
    address_name      = models.CharField(max_length=50, null=False, blank=True)
    first_name        = models.CharField(max_length=50, null=False, blank=True)
    last_name         = models.CharField(max_length=50, null=False,blank=True)
    email             = models.EmailField()
    address_1         = models.CharField(max_length=250, blank=True)
    address_2         = models.CharField(max_length=250, blank=True)
    country           = models.CharField(max_length=15)
    state             = models.CharField(max_length=15)
    city              = models.CharField(max_length=15)
    pin               = models.IntegerField()
    is_deleted        = models.BooleanField(default=False)
    default           = models.BooleanField(default=False)
    objects = models.Manager()
    def __str__(self):
        return f"{self.address_name} "
    
class CityDistance(models.Model):
    user = models.OneToOneField(Customer, on_delete=models.CASCADE)
    distance = models.FloatField()
    price = models.DecimalField(max_digits=10, decimal_places=2)  # Add price field

    def __str__(self):
        return f"City Distance for {self.user.email}"



class Coupon(models.Model):
    coupon_code = models.CharField(max_length=50, unique=True)
    discount_amount = models.PositiveIntegerField(default=100)
    # expiration_date = models.DateTimeField()
    max_usage_count = models.IntegerField(default=1)
    min_amount = models.IntegerField(default=0)
    current_usage_count = models.IntegerField(default=0)
    # created_at = models.DateTimeField(default=timezone.now)

    def is_expired(self):
        return self.expiration_date <= timezone.now()

    def is_max_usage_reached(self):
        return self.current_usage_count >= self.max_usage_count

    def __str__(self):
        return self.coupon_code


class Cart(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True, blank=True)
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, null=True, blank=True
    )
    quantity = models.IntegerField(default=0)
    image = models.ImageField(upload_to="products", null=True, blank=True)
    coupon = models.ForeignKey(Coupon,on_delete=models.SET_NULL, null=True, blank=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0)


    @property
    def sub_total(self):
        return self.product.price * self.quantity

    def __str__(self):
        return (
            f"Cart: {self.user.username} - {self.product} - Quantity: {self.quantity}"
        )
    



class Wishlist(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True, blank=True)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    image = models.ImageField(upload_to="products", null=True, blank=True)
    device = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f"Wishlist:{self.user.username}-{self.product}"
    



class Order(models.Model):
    ORDER_STATUS = (
        ("pending", "Pending"),
        ("processing", "processing"),
        ("shipped", "shipped"),
        ("delivered", "delivered"),
        ("completed", "Completed"),
        ("cancelled", "Cancelled"),
        ("refunded", "refunded"),
        ("on_hold", "on_hold"),
    )

    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='order_user')
    address = models.ForeignKey(Address, on_delete=models.CASCADE, related_name='order_address')
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, null=True, blank=True, related_name='order_product'
    )

    amount = models.DecimalField(max_digits=12, decimal_places=2)
    payment_type = models.CharField(max_length=100)
    status = models.CharField(max_length=100, choices=ORDER_STATUS, default="pending")
    quantity = models.IntegerField(default=0, null=True, blank=True)
    image = models.ImageField(upload_to="products", null=True, blank=True)
    date = models.DateField(default=date.today)


    def __str__(self):
        return f"Order #{self.pk} - {self.product}"
    

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='order_items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='orderitem_product')
    quantity = models.IntegerField(default=1)
    image = models.ImageField(upload_to="products", null=True, blank=True)

    def __str__(self):
        return str(self.id)
    



class Wallet(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    is_credit = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    status=models.CharField(max_length=20,blank=True)
    add_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True)

    def _str_(self):
        return f"{self.amount} {self.is_credit}"

    def _iter_(self):
        yield self.pk



class Banner(models.Model):
    image = models.ImageField(upload_to='product_images', blank=True, null=True)
    title = models.CharField(max_length=100)
    description = models.TextField()
    url = models.CharField(max_length=100, blank=True, null=True)
    deleted = models.BooleanField(default=False)
    objects = models.Manager()
    
    def __str__(self):
        return self.title