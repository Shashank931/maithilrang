from django.urls import path
from core.views import home , login , signup , aboutus , paintings ,contactus , product_details

urlpatterns = [
    path('',home, name = 'home' ),
    path('login/',login, name = 'login' ),
    path('signup/',signup, name = 'signup' ),
    path('aboutus/',aboutus, name = 'aboutus' ),
    path('contactus/',contactus, name = 'contactus' ),
    path('paintings/',paintings, name = 'paintings' ),
    path('paintings/<slug:category_slug>/',paintings, name = 'paintings_by_category' ),
    path('paintings/<slug:category_slug>/<slug:product_slug>/',product_details, name = 'product_details' ),

]