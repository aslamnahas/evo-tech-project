from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from . import views
app_name = "adminside"


urlpatterns = [
    path('', views.admin_login,name='admin_login'),
    path('dashboard/',views.dashboard,name='dashboard'),
    path('logout/',views.dashboard_logout,name='dashboard_logout'),
    path('user/',views.users,name='users'),
    path('user_block/<int:user_id>/', views.user_block, name='user_block'),

    path('categories/',views.main_category,name='categories'),
    path('add_main_category/',views.add_main_category,name='add_main_category'),
    path('update_main_category/<int:id>/',views.update_main_category,name='update_main_category'),
    path('soft_delete_category/<int:id>/',views.soft_delete_category,name='soft_delete_category'), 
    path('delete_main_category/<int:id>/',views.delete_main_category,name='delete_main_category'), 

    # Other URL patterns


    path('products/',views.products,name='products'),
    path('add_product/',views.add_product,name='add_product'),
    path('update_product/<int:id>/',views.update_product,name='update_product'),
    path('soft_delete_product/<int:id>/',views.soft_delete_product,name='soft_delete_product'),
    path('home/',views.home,name='home'),
    path('report-pdf-order/', views.report_pdf_order, name='report_pdf_order'),
    
    
    path('banners/',views.banners,name='banners'), 
    path('add_banners/',views.add_banners,name='add_banners'), 
    path('update_banners/<int:id>/',views.update_banners,name='update_banners'), 
    path('delete_banner/<int:id>/',views.delete_banner,name='delete_banner'),



]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
