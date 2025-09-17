from django.conf import settings
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
import datetime
from orders.forms import OrderForm
from orders.models import Order ,Payment,Refund,OrderProduct
import razorpay
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse , HttpResponseBadRequest,HttpResponse
import hmac
import hashlib
import json
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse
from django.template.loader import get_template
from xhtml2pdf import pisa
from accounts.forms import ProfileForm

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


def payments(req):
    return render(req , 'core/payments.html')



client= razorpay.Client(auth=(settings.RAZORPAY_KEY_ID,settings.RAZORPAY_KEY_SECRET))

def place_order(req ,total = 0 , quantity = 0 ):
    current_user = req.user

    # if  the cart count is less than or equal to 0 then redirect  back to shop 

    cart_items = CartItem.objects.filter(user = current_user)
    cart_count = cart_items.count() 
    if cart_count <=0:
        return redirect('paintings')
    

    grand_total = 0
    tax = 0
    for cart_item in cart_items:
        total += (cart_item.product.price * cart_item.quantity)
        quantity += cart_item.quantity
    tax = (2*total)/100
    grand_total = total + tax
    amount_in_paise = int(grand_total * 100)
    

    if req.method =='POST':
        form = OrderForm(req.POST)
        if form.is_valid():
            # store all the billing information inside  order table
            data = Order()
            data.user = current_user
            data.first_name = form.cleaned_data['first_name']
            data.last_name = form.cleaned_data['last_name']
            data.phone = form.cleaned_data['phone']
            data.email = form.cleaned_data['email']
            data.address = form.cleaned_data['address']
            data.country = form.cleaned_data['country']
            data.state = form.cleaned_data['state']
            data.city = form.cleaned_data['city']
            data.zipcode = form.cleaned_data['zipcode']
            data.note = form.cleaned_data['note']
            data.order_total = grand_total
            data.tax = tax
            data.ip = req.META.get('REMOTE_ADDR')
            data.save()
            #Generate order number
            yr = int(datetime.date.today().strftime('%Y'))
            dt = int(datetime.date.today().strftime('%d'))
            mt = int(datetime.date.today().strftime('%m'))
            d  = datetime.date(yr ,mt, dt)
            current_date = d.strftime("%Y%m%d")
            order_number = current_date + str(data.id)
            data.order_number = order_number
            data.save()

              # Create Razorpay Order
            razorpay_order = client.order.create({
            "amount":  amount_in_paise,    # in paise
            "currency": "INR",
            "payment_capture": "1"
            })

            payment = Payment.objects.create(
            user=current_user,
            payment_id="",  # will fill after success
            payment_method="Razorpay",
            razorpay_order_id=razorpay_order['id'],
            amount_paid=grand_total,
            status="Pending",
            transaction_details= razorpay_order 
        )
             # link in our Order
            order = Order.objects.get(user = current_user , is_ordered = False ,order_number = order_number ) 
            order.razorpay_order_id = razorpay_order['id']
            order.payment = payment
            order.save()

            context ={
                'order':order,
                'cart_items': cart_items,
                'total':total,
                'tax': tax,
                'grand_total':grand_total,
                "amount_in_paise": amount_in_paise, 
                'razorpay_order_id': razorpay_order['id'],
                'razorpay_merchant_key': settings.RAZORPAY_KEY_ID,
                'currency': 'INR',
               'callback_url': f"{req.scheme}://{req.get_host()}{reverse('razorpay_callback')}",
                'fail_redirect_url': req.build_absolute_uri('failed/'),
            }
            return render(req, 'core/payments.html' ,context) 
    else:
        return redirect('checkout')
   

@csrf_exempt
def razorpay_callback(request):
    if request.method == "POST":
        try:
            data = request.POST
            print("CALLBACK DATA:", data)

            razorpay_order_id = data.get("razorpay_order_id")
            razorpay_payment_id = data.get("razorpay_payment_id")
            razorpay_signature = data.get("razorpay_signature")

            order = get_object_or_404(Order, razorpay_order_id=razorpay_order_id)
            payment = order.payment

            params_dict = {
                "razorpay_order_id": razorpay_order_id,
                "razorpay_payment_id": razorpay_payment_id,
                "razorpay_signature": razorpay_signature,
            }

            try:
                # 🔹 Verify Razorpay signature
                client.utility.verify_payment_signature(params_dict)

                # 🔹 Update Payment
                payment.payment_id = razorpay_payment_id
                payment.razorpay_signature = razorpay_signature
                payment.status = "Completed"
                payment.transaction_details = dict(data)
                payment.save()

                # 🔹 Update Order
                order.payment = payment
                order.is_ordered = True
                order.status = "Accepted"
                order.save()

                # 🔹 Move cart items to OrderProduct
                cart_items = CartItem.objects.filter(user=order.user)
                for item in cart_items:
                    OrderProduct.objects.create(
                        order=order,
                        payment=payment,
                        user=order.user,
                        product=item.product,
                        quantity=item.quantity,
                        product_price=item.product.price,
                        ordered=True,
                    )

                    # reduce stock
                    item.product.stock -= item.quantity
                    item.product.save()

                # clear cart
                cart_items.delete()

                # 🔹 Send Order Confirmation Mail (only once ✅)
                try:
                    mail_subject = "Thank you for your order!"
                    message = render_to_string(
                        "core/order_received.html", {"user": order.user, "order": order}
                    )
                    send_email = EmailMessage(mail_subject, message, to=[order.user.email])
                    send_email.send()
                except Exception as e:
                    print("⚠️ Email sending failed:", str(e))

                print("✅ Order placed successfully!")
                return redirect("payment_success_page")

            except razorpay.errors.SignatureVerificationError:
                print("❌ Signature verification failed")
                payment.status = "Failed"
                payment.save()
                return redirect("payment_failed_page")

        except Exception as e:
            print("❌ Callback error:", str(e))
            return redirect("payment_failed_page")

    return JsonResponse({"status": "Invalid request"}, status=400)



@csrf_exempt
def razorpay_webhook(request):
    if request.method == "POST":
        try:
            # 1. Razorpay payload + signature निकालो
            payload = request.body.decode('utf-8')
            received_signature = request.headers.get('X-Razorpay-Signature')

            # 2. Webhook signature verify करो
            secret = settings.RAZORPAY_WEBHOOK_SECRET.encode()
            generated_signature = hmac.new(
                secret,
                msg=payload.encode(),
                digestmod=hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(received_signature, generated_signature):
                return HttpResponseBadRequest("Invalid Signature")

            # 3. Parse JSON payload
            data = json.loads(payload)
            event = data.get("event")

            # 4. Event के हिसाब से action लो
            if event == "payment.captured":
                payment_id = data["payload"]["payment"]["entity"]["id"]
                razorpay_order_id = data["payload"]["payment"]["entity"]["order_id"]

                payment = Payment.objects.filter(razorpay_order_id=razorpay_order_id).first()
                if payment:
                    payment.payment_id = payment_id
                    payment.status = "Success"
                    payment.save()

                    # Order को mark करो
                    order = Order.objects.filter(razorpay_order_id=razorpay_order_id).first()
                    if order:
                        order.is_ordered = True
                        order.save()

            elif event == "payment.failed":
                razorpay_order_id = data["payload"]["payment"]["entity"]["order_id"]
                payment = Payment.objects.filter(razorpay_order_id=razorpay_order_id).first()
                if payment:
                    payment.status = "Failed"
                    payment.save()

            elif event == "refund.processed":
                razorpay_payment_id = data["payload"]["refund"]["entity"]["payment_id"]
                payment = Payment.objects.filter(payment_id=razorpay_payment_id).first()
                if payment:
                    payment.status = "Refunded"
                    payment.save()

            return JsonResponse({"status": "ok"})
        except Exception as e:
            return HttpResponseBadRequest(str(e))
    else:
        return HttpResponseBadRequest("Invalid Method")


@staff_member_required
def refund_payment(request, payment_id):
    payment = get_object_or_404(Payment, id=payment_id)

    if not payment.payment_id:
        return HttpResponseBadRequest("No captured payment_id to refund.")

    try:
        # Razorpay refund API
        refund_response = client.payment.refund(
            payment.payment_id,
            {
                "amount": int(payment.amount_paid * 100),  # Full refund (paise)
                "speed": "optimum"  # "optimum" or "normal"
            }
        )

        # Save refund record
        refund = Refund.objects.create(
            payment=payment,
            refund_id=refund_response["id"],
            amount=payment.amount_paid,
            reason="Customer requested refund",
            status="Processed"
        )

        # Update Payment status
        payment.status = "Refunded"
        payment.save()

        return HttpResponse(f"Refund successful. Refund ID: {refund.refund_id}")

    except Exception as e:
        # If refund failed
        Refund.objects.create(
            payment=payment,
            amount=payment.amount_paid,
            reason=str(e),
            status="Failed"
        )
        return HttpResponseBadRequest(f"Refund failed: {str(e)}")




def payment_success_page(request):
    try:
        # ✅ Latest successful order nikal lo user ka
        order = Order.objects.filter(user=request.user, is_ordered=True).latest('created_at')
        order_products = OrderProduct.objects.filter(order=order)
    except Order.DoesNotExist:
        order = None
        order_products = []

    # ----- Calculate Totals -----
    total = 0
    for item in order_products:
        item.item_total = item.product_price * item.quantity  # 👈 per-item total
        total += item.item_total

    tax = order.tax if order else 0
    shipping_charge = order.shipping_charge if order else 0
    grand_total = total + tax + shipping_charge

    return render(request, "core/payment_success.html", {
        "order": order,
        "order_products": order_products,
        "payment": order.payment if order else None,
        "total": total,
        "tax": tax,
        "shipping_charge": shipping_charge,
        "grand_total": grand_total,
    })


def payment_failed_page(request):
    return render(request, 'core/payment_failed.html')



@login_required
def dashboard(request):
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    total_orders = orders.count()
    pending_orders = orders.filter(status="Pending").count()
    recent_orders = orders[:5]  # sirf last 5 orders dikhane ke liye
    
    context = {
        "total_orders": total_orders,
        "pending_orders": pending_orders,
        "recent_orders": recent_orders,
    }
    return render(request, "core/dashboard.html", context)



@login_required(login_url='login')
def my_orders(request):
    orders = Order.objects.filter(user=request.user).order_by('-created_at')
    context = {
        'orders': orders,
    }
    return render(request, 'core/my_orders.html', context)


@login_required(login_url='login')
def order_detail(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    order_products = OrderProduct.objects.filter(order=order)

    context = {
        'order': order,
        'order_products': order_products,
    }
    return render(request, 'core/order_detail.html', context)




@login_required
def invoice_view(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user, is_ordered=True)
    order_products = OrderProduct.objects.filter(order=order)
    payment = order.payment

    # ----- Calculate Totals -----
    total = 0
    for item in order_products:
        item.item_total = item.product_price * item.quantity  # per-item total
        total += item.item_total

    tax = order.tax
    shipping_charge = order.shipping_charge
    grand_total = total + tax + shipping_charge

    context = {
        "order": order,
        "order_products": order_products,
        "payment": payment,
        "total": total,
        "tax": tax,
        "shipping_charge": shipping_charge,
        "grand_total": grand_total,
    }
    return render(request, "core/invoice.html", context)


@login_required
def download_invoice(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user, is_ordered=True)
    order_products = OrderProduct.objects.filter(order=order)
    payment = order.payment

    # ----- Calculate Totals -----
    total = 0
    for item in order_products:
        item.item_total = item.product_price * item.quantity  # per-item total
        total += item.item_total

    tax = order.tax
    shipping_charge = order.shipping_charge
    grand_total = total + tax + shipping_charge

    # Render template with context
    template = get_template('core/invoice_pdf.html')
    html = template.render({
        "order": order,
        "order_products": order_products,
        "payment": payment,
        "total": total,
        "tax": tax,
        "shipping_charge": shipping_charge,
        "grand_total": grand_total,
    })

    # Generate PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Invoice_{order.order_number}.pdf"'
    pisa.CreatePDF(html, dest=response)

    return response


@login_required
def profile_view(request):
    user = request.user  # logged-in user ka data
    context = {
        "user": user,
    }
    return render(request, "core/profile.html", context)



@login_required
def edit_profile(request):
    user = request.user
    if request.method == "POST":
        form = ProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, "✅ Profile updated successfully!")
            return redirect("profile_view")  # redirect back to profile page
    else:
        form = ProfileForm(instance=user)

    return render(request, "core/edit_profile.html", {"form": form})


def aboutus(req):
    
    return render(req, 'core/aboutus.html')


def contactus(req):
    return render(req, 'core/contactus.html')
