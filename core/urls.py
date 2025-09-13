from django.urls import path
from core.views import home , login , signup , aboutus , paintings ,contactus , product_details , cart , add_cart , remove_cart , remove_cart_item , search , logout ,activate , dashboard ,forgot_password , resetpassword_validate , resetPassword , checkout , place_order , payments ,razorpay_callback , razorpay_webhook,refund_payment,payment_failed_page,payment_success_page , my_orders ,order_detail , invoice_view , download_invoice
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


    path ('activate/<uidb64>/<token>/' , activate , name='activate'),

    path('dashboard/', dashboard , name='dashboard'),
    path("orders/", my_orders, name="my_orders"),
    path("orders/<str:order_id>/", order_detail, name="order_detail"),

    path('forgot_password/', forgot_password , name='forgot_password'),
    
    path ('resetpassword_validate/<uidb64>/<token>/' , resetpassword_validate , name='resetpassword_validate'),

    path('resetPassword/', resetPassword , name='resetPassword'),

    path('checkout/', checkout , name='checkout'),


    path('place_order/', place_order , name='place_order'),

    path('payments/', payments , name='payments'),

    path('razorpay/callback/', razorpay_callback, name='razorpay_callback'),
    path('razorpay/webhook/', razorpay_webhook, name='razorpay_webhook'),
    path('place_order/success/', payment_success_page, name='payment_success_page'),
    path('place_order/failed/', payment_failed_page, name='payment_failed_page'),
    path("payments/<int:payment_id>/refund/", refund_payment, name="refund_payment"),
     path('invoice/<int:order_id>/', invoice_view, name='invoice_view'),
    path('invoice/download/<int:order_id>/',download_invoice, name='download_invoice'),





    ]