from django.shortcuts import render, get_object_or_404, redirect
from store.models import Product
from category.models import Category
from carts.models import Cart, CartItem
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from accounts.forms import SignupForm
from accounts.models import Account
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password, ValidationError
import requests

# verification email files
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage


# Helper function for cart totals
def get_cart_totals(cart_items):
    total = sum(item.product.price * item.quantity for item in cart_items)
    tax = (2 * total) / 100
    return total, tax, total + tax


def _cart_id(request):
    cart = request.session.session_key
    if not cart:
        cart = request.session.create()
    return cart


def home(req):
    products = Product.objects.filter(is_available=True)
    context = {
        'products': products,
    }
    return render(req, 'core/home.html', context)


def paintings(req, category_slug=None):
    if category_slug is not None:
        categories = get_object_or_404(Category, slug=category_slug)
        products = Product.objects.filter(category=categories, is_available=True)
    else:
        products = Product.objects.filter(is_available=True)

    context = {
        'products': products,
    }
    return render(req, 'core/paintings.html', context)


def product_details(req, category_slug, product_slug):
    single_product = get_object_or_404(Product, category__slug=category_slug, slug=product_slug)
    context = {
        'single_product': single_product,
    }
    return render(req, 'core/product_details.html', context)


def add_cart(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    if request.user.is_authenticated:
        # User logged in → store directly in user's cart
        cart_item, created = CartItem.objects.get_or_create(
            product=product,
            user=request.user,
            defaults={'quantity': 1}
        )
        if not created:
            cart_item.quantity += 1
            cart_item.save()
    else:
        # Guest user → store in session cart
        try:
            cart = Cart.objects.get(cart_id=_cart_id(request))
        except Cart.DoesNotExist:
            cart = Cart.objects.create(cart_id=_cart_id(request))
        cart.save()

        cart_item, created = CartItem.objects.get_or_create(
            product=product,
            cart=cart,
            defaults={'quantity': 1}
        )
        if not created:
            cart_item.quantity += 1
            cart_item.save()

    return redirect('cart')


def remove_cart(req, product_id):
    product = get_object_or_404(Product, id=product_id)

    if req.user.is_authenticated:
        cart_item = CartItem.objects.get(product=product, user=req.user)
    else:
        cart = Cart.objects.get(cart_id=_cart_id(req))
        cart_item = CartItem.objects.get(product=product, cart=cart)

    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        cart_item.save()
    else:
        cart_item.delete()
    return redirect('cart')



def remove_cart_item(req, product_id):
    product = get_object_or_404(Product, id=product_id)

    if req.user.is_authenticated:
        CartItem.objects.filter(product=product, user=req.user).delete()
    else:
        cart = Cart.objects.get(cart_id=_cart_id(req))
        CartItem.objects.filter(product=product, cart=cart).delete()

    return redirect('cart')



def cart(req):
    try:
        if req.user.is_authenticated:
            cart_items = CartItem.objects.filter(user=req.user, is_active=True).select_related('product')
        else:
            cart = Cart.objects.get(cart_id=_cart_id(req))
            cart_items = CartItem.objects.filter(cart=cart, is_active=True).select_related('product')

        total, tax, grand_total = get_cart_totals(cart_items)
    except ObjectDoesNotExist:
        cart_items, total, tax, grand_total = None, 0, 0, 0

    context = {
        'total': total,
        'quantity': sum(item.quantity for item in cart_items) if cart_items else 0,
        'cart_items': cart_items,
        'tax': tax,
        'grand_total': grand_total,
    }
    return render(req, 'core/cart.html', context)


def search(req):
    products = []
    if 'keyword' in req.GET:
        keyword = req.GET['keyword']
        if keyword:
            products = Product.objects.order_by('-created_date').filter(
                Q(description__icontains=keyword) | Q(product_name__icontains=keyword)
            )
    context = {
        'products': products,
    }
    return render(req, 'core/paintings.html', context)


def login(req):
    if req.method == 'POST':
        email = req.POST['email']
        password = req.POST['password']
        user = auth.authenticate(request=req, email=email, password=password)  # fixed for custom user model

        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(req))
                if CartItem.objects.filter(cart=cart).exists():
                    for item in CartItem.objects.filter(cart=cart):
                        existing_item = CartItem.objects.filter(user=user, product=item.product).first()
                        if existing_item:
                            existing_item.quantity += item.quantity
                            existing_item.save()
                            item.delete()
                        else:
                            item.user = user
                            item.save()
            except Cart.DoesNotExist:
                pass
            auth.login(req, user)
            url = req.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)
            except:
                return redirect('home')

        else:
            messages.error(req, "Invalid login credentials")
            return redirect('login')
    return render(req, 'core/login.html')


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

            # user activation email (send asynchronously in production)
            current_site = get_current_site(req)
            mail_subject = 'Please activate your account'
            message = render_to_string('core/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            send_email = EmailMessage(mail_subject, message, to=[email])
            send_email.send()

            return redirect(f'/login/?command=verification&email={email}')
        else:
            messages.error(req, "Registration failed. Something went wrong!")
    else:
        form = SignupForm()

    return render(req, 'core/signup.html', {'form': form})


def activate(req, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(req, 'Congratulations! Your account is activated.')
        return redirect('login')
    else:
        messages.error(req, 'Invalid activation link')
        return redirect('signup')


def dashboard(req):
    return render(req, 'core/dashboard.html')


def forgot_password(req):
    if req.method == 'POST':
        email = req.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
            current_site = get_current_site(req)
            mail_subject = 'Reset Your Password'
            message = render_to_string('core/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            send_email = EmailMessage(mail_subject, message, to=[email])
            send_email.send()

            messages.success(req, 'Password reset email has been sent to your email address')
            return redirect('login')
        else:
            messages.error(req, 'Account does not exist!')
            return redirect('forgot_password')
    return render(req, 'core/forgot_password.html')


def resetpassword_validate(req, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        req.session['uid'] = uid
        messages.success(req, 'Please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(req, 'This link has expired!')
        return redirect('login')


def resetPassword(req):
    if req.method == 'POST':
        password = req.POST.get('password')
        confirm_password = req.POST.get('confirm_password')

        if password != confirm_password:
            messages.error(req, "Passwords do not match.")
            return redirect('resetPassword')

        uid = req.session.get('uid')
        if not uid:
            messages.error(req, "Session expired. Please try again.")
            return redirect('forgotPassword')

        try:
            user = Account.objects.get(pk=uid)
        except ObjectDoesNotExist:
            messages.error(req, "User not found.")
            return redirect('forgotPassword')

        try:
            validate_password(password, user)
        except ValidationError as e:
            messages.error(req, " ".join(e))
            return redirect('resetPassword')

        user.set_password(password)
        user.save()
        req.session.pop('uid', None)

        messages.success(req, "Password reset successful. Please login.")
        return redirect('login')

    return render(req, 'core/resetPassword.html')


@login_required(login_url='login')
def checkout(req):
    try:
        if req.user.is_authenticated:
            cart_items = CartItem.objects.filter(user=req.user, is_active=True).select_related('product')
        else:
            cart = Cart.objects.get(cart_id=_cart_id(req))
            cart_items = CartItem.objects.filter(cart=cart, is_active=True).select_related('product')

        total, tax, grand_total = get_cart_totals(cart_items)
    except ObjectDoesNotExist:
        cart_items, total, tax, grand_total = None, 0, 0, 0

    context = {
        'total': total,
        'quantity': sum(item.quantity for item in cart_items) if cart_items else 0,
        'cart_items': cart_items,
        'tax': tax,
        'grand_total': grand_total,
    }
    return render(req, 'core/checkout.html', context)


def aboutus(req):
    return render(req, 'core/aboutus.html')


def contactus(req):
    return render(req, 'core/contactus.html')
