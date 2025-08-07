from django.shortcuts import render , get_object_or_404 , redirect
from store.models import Product
from category.models import Category
from carts.models import Cart , CartItem 
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from accounts.forms import SignupForm
from accounts.models import Account
from django.contrib import messages ,auth
from django.contrib.auth.decorators import login_required

# verifiction email files
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode , urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

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
    if req.method == 'POST':
        email = req.POST['email']
        password = req.POST['password']
        print("🟡 Login attempt:", email, password)

        user = auth.authenticate(username =email , password =password)
        print("🔵 Authenticated user:", user)

        if user is not None:
            auth.login(req ,user)
            print("🟢 Login successful")
            # messages.success(req, 'You are now logged in.')
            return redirect('home')
        else:
            print("🔴 Login failed: Invalid credentials")
            messages.error(req,"Invalid login credentials")
            return redirect('login')
    return render(req , 'core/login.html')



@login_required(login_url='login')
def logout(req):
    auth.logout(req)
    messages.success(req, 'You are logged out!')
    return redirect('login')


def signup(req):
    if req.method == 'POST':
        form = SignupForm(req.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split("@")[0]

            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password
            )
            user.phone_number = phone_number
            user.save()


            #user activation
            current_site = get_current_site(req)
            mail_subject = 'Please activation your account'
            message = render_to_string('core/account_verification_email.html' ,{
                'user':user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token':default_token_generator.make_token(user),


            })
            to_email = email
            send_email = EmailMessage(mail_subject,message , to=[to_email])
            send_email.send()


            # messages.success(req, "Thank you for registering with us .we have sent you a verification email on your register email. please verify it.")
            
            return redirect('/login/?command=verification&email={email}')
        else:
            messages.error(req, "Registration Faild. Something Went Wrong!")
    else:
        form = SignupForm()

    return render(req, 'core/signup.html', {'form': form})



def activate(req , uidb64 ,token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user , token):
        user.is_active =True
        user.save()
        messages.success(req, 'Congratulations! Your account is actvated.')
        return redirect('login')
    else:
        messages.error(req, 'Invalid activation link')
        return redirect('signup')

def aboutus(req):
    return render(req , 'core/aboutus.html')

def contactus(req):
    return render(req, 'core/contactus.html')

