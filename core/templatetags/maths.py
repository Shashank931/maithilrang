from django import template

register = template.Library()

@register.filter
def mul(value, arg):
    """Django template filter for multiplication"""
    try:
        return float(value) * float(arg)
    except:
        return 0
