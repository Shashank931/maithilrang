from django.db import models
from accounts.models import Account
from store.models import Product
from decimal import Decimal


class Payment(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
        ('Refunded', 'Refunded'),
        ('Failed', 'Failed'),
    )

    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    payment_id = models.CharField(max_length=100)
    payment_method = models.CharField(max_length=20)
    razorpay_order_id = models.CharField(max_length=100, blank=True, null=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)

    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    transaction_details = models.JSONField(blank=True, null=True)  # ✅ Payment gateway ka raw response
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.payment_id


class Order(models.Model):
    STATUS = (
        ('New', 'New'),
        ('Accepted', 'Accepted'),
        ('Shipped', 'Shipped'),
        ('Completed', 'Completed'),
        ('Cancelled', 'Cancelled'),
        ('Returned', 'Returned'),
    )

    user = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, blank=True, null=True)
    razorpay_order_id = models.CharField(max_length=100, blank=True, null=True)
    order_number = models.CharField(max_length=20)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    phone = models.CharField(max_length=15)
    email = models.EmailField(max_length=50)
    address = models.CharField(max_length=255)
    country = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    zipcode = models.CharField(max_length=10)
    order_total = models.DecimalField(max_digits=10, decimal_places=2)
    tax = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_charge = models.DecimalField(max_digits=10, decimal_places=2, default=0 , blank=True, null=True)  # ✅ Shipping cost
    shipping_method = models.CharField(max_length=50, blank=True, null=True)  # ✅ Standard/Express
    tracking_number = models.CharField(max_length=100, blank=True, null=True)  # ✅ Courier tracking ID
    delivered_at = models.DateTimeField(blank=True, null=True)  # ✅ Delivery date & time
    note = models.TextField(blank=True, null=True)  # ✅ Customer note
    status = models.CharField(max_length=10, choices=STATUS, default='New')
    ip = models.GenericIPAddressField(blank=True, null=True)
    is_ordered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def full_name(self):
        return f'{self.first_name} {self.last_name}'
    def __str__(self):
        return f"Order {self.order_number}"



class OrderProduct(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    payment = models.ForeignKey(Payment, on_delete=models.SET_NULL, blank=True, null=True)
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    product_price = models.DecimalField(max_digits=10, decimal_places=2)
    ordered = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.product.product_name if self.product else "Deleted Product"

class Refund(models.Model):
    payment = models.ForeignKey("Payment", on_delete=models.CASCADE, related_name="refunds")
    refund_id = models.CharField(max_length=100, blank=True, null=True)  # Razorpay refund_id
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    reason = models.TextField(blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ("Initiated", "Initiated"),
            ("Processed", "Processed"),
            ("Failed", "Failed"),
        ],
        default="Initiated"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Refund {self.refund_id} - {self.status}"
