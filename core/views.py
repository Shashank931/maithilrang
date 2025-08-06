from django.shortcuts import render , get_object_or_404 , redirect
from store.models import Product
from category.models import Category
from carts.models import Cart , CartItem 
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q


# Create your views here.

def _cart_id(request):
    cart = request.session.session_key
    if not cart:
        cart = request.session.create()
    return cart



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

        # in_cart = CartItem.objects.filter(cart__cart_id = _cart_id(req) , product = single_product).exists()
    except Exception as e:
        raise e
    
    context ={
        'single_product' : single_product,
        # 'in_cart' : in_cart
    }

    return render(req , 'core/product_details.html' , context)





def add_cart(request , product_id ):
    product = Product.objects.get(id=product_id) #get the product
    try:
        cart = Cart.objects.get(cart_id=_cart_id(request)) # get the cart using the cart _id present in the session
    except Cart.DoesNotExist:
        cart = Cart.objects.create(
            cart_id = _cart_id(request)
        )
    cart.save()

    try:
        cart_item = CartItem.objects.get(product=product , cart = cart)
        cart_item.quantity += 1 #cart_item.quantity = cart+item.quantity+1
        cart_item.save()
    except CartItem.DoesNotExist:
        cart_item = CartItem.objects.create(
            product = product, 
            quantity =1 ,
            cart = cart,
        )
        cart_item.save()
    return redirect('cart')

def remove_cart(req , product_id):
    cart = Cart.objects.get(cart_id = _cart_id(req))
    product = get_object_or_404(Product , id=product_id)
    cart_item = CartItem.objects.get(product = product , cart=cart)
    if cart_item.quantity>1:
        cart_item.quantity -=1
        cart_item.save()
    else:
        cart_item.delete()
    return redirect('cart')


def remove_cart_item (req , product_id):
    cart = Cart.objects.get(cart_id = _cart_id(req))
    product = get_object_or_404(Product, id=product_id)
    cart_item = CartItem.objects.get(product=product , cart= cart)
    cart_item.delete()
    return redirect ('cart')







def cart(req, total=0, quantity=0):
    try:
        tax =0
        grand_total = 0
        cart = Cart.objects.get(cart_id=_cart_id(req))
        cart_items = CartItem.objects.filter(cart=cart, is_active=True)
        for item in cart_items:
            total += (item.product.price * item.quantity)
            quantity += item.quantity
        tax = (2 * total)/100
        grand_total = total+tax
    except ObjectDoesNotExist:
        cart_items = []

    context = {
        'total': total,
        'quantity': quantity,
        'cart_items': cart_items,  
        'tax' : tax,
        'grand_total' : grand_total,

    }

    return render(req, 'core/cart.html', context)



def search(req):
    products = [] 
    if 'keyword' in req.GET:
        keyword = req.GET['keyword']
        if keyword:
            products = Product.objects.order_by('-created_date').filter(Q(description__icontains=keyword) | Q( product_name__icontains = keyword))
            
    context ={
        'products':products,
    }
    return render(req , 'core/paintings.html' , context)


def login(req):
    return render(req , 'core/login.html')

def signup(req):
    return render(req , 'core/signup.html')

def aboutus(req):
    return render(req , 'core/aboutus.html')

def contactus(req):
    return render(req, 'core/contactus.html')

