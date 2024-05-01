from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin,Group,Permission
from django.db import models
from django.utils import timezone

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
    




class Cart(models.Model):
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True, blank=True)
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, null=True, blank=True
    )
    quantity = models.IntegerField(default=0)
    image = models.ImageField(upload_to="products", null=True, blank=True)
   

    @property
    def sub_total(self):
        return self.product.price * self.quantity

    def __str__(self):
        return (
            f"Cart: {self.user.username} - {self.product} - Quantity: {self.quantity}"
        )