from django.shortcuts import render , get_object_or_404
from store.models import Product
from category.models import Category

# Create your views here.

def home(req):
    products= Product.objects.all().filter(is_available = True)
    context ={
        'products':products,
    }
    return render(req,'core/home.html' , context)




def paintings(req , category_slug=None):
    categories = None
    products = None

    if category_slug != None:
        categories = get_object_or_404(Category , slug=category_slug)
        products =Product.objects.filter(category = categories ,is_available = True)
        
    else:
        products= Product.objects.all().filter(is_available = True)


    context ={
        'products':products,
    }
    return render(req, 'core/paintings.html' , context)





def product_details(req , category_slug , product_slug):
    try:
        single_product = Product.objects.get(category__slug=category_slug , slug = product_slug )
    except Exception as e:
        raise e
    
    context ={
        'single_product' : single_product,
    }

    return render(req , 'core/product_details.html' , context)



def login(req):
    return render(req , 'core/login.html')

def signup(req):
    return render(req , 'core/signup.html')

def aboutus(req):
    return render(req , 'core/aboutus.html')

def contactus(req):
    return render(req, 'core/contactus.html')

