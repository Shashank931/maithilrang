from django.urls import path
from core.views import home , login , signup , aboutus , paintings ,contactus , product_details , cart , add_cart , remove_cart , remove_cart_item , search , logout ,activate
urlpatterns = [

    path('',home, name = 'home' ),

    path('login/',login, name = 'login' ),

    path('signup/',signup, name = 'signup' ),

    path('logout/',logout, name = 'logout' ),

    path('aboutus/',aboutus, name = 'aboutus' ),

    path('contactus/',contactus, name = 'contactus' ),

    path('paintings/',paintings, name = 'paintings' ),

    path('paintings/category/<slug:category_slug>/',paintings, name = 'paintings_by_category' ),

    path('paintings/category/<slug:category_slug>/<slug:product_slug>/',product_details, name = 'product_details' ),

    path('cart/', cart , name='cart'),
    path('add_cart/<int:product_id>/' , add_cart , name = 'add_cart'),
    path('remove_cart/<int:product_id>/' , remove_cart , name = 'remove_cart'),
    path('remove_cart_item/<int:product_id>/' , remove_cart_item , name = 'remove_cart_item'),

    path ('paintings/search/' , search , name='search'),


    path ('activate/<uidb64>/<token>/' , activate , name='activate')

]