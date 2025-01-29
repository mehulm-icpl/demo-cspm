from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import MinimumLengthValidator, CommonPasswordValidator, NumericPasswordValidator
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import warnings, logging
from django.conf.urls import handler404

handler404_usermanagement = handler404

def index(request):
    return render(request, 'index.html')

#-------------------------------- user login -------------------------------------------------
# Define your logger
logger = logging.getLogger(__name__)

def user_login(request):
    logout(request)
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('user-password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            try:
                if user.awsmodal.aws_account_id is None:
                    return redirect('services')
                else:
                    return redirect('services')
            except Exception as e:
                # Log the exception for debugging purposes
                logger.error(f"Error checking AWS account ID: {str(e)}")
                return redirect('services')
        else:
            messages.error(request, 'Invalid username or password.')
            return render(request, 'login.html')
    elif request.method == 'GET':
        return render(request, 'login.html')
    else:
        return render(request, 'error_404.html')

# ------------------------------------- USER REAGESTER --------------------------------

def register(request):
    if request.method == 'POST':
        try:
            if 'my_checkbox' in request.POST:
                checkbox_value = True
            else:
                checkbox_value = False
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            email = request.POST.get('email')
            username = request.POST.get('username')
            user_password = request.POST.get('user-password')
            # create a user
            if is_valid_email(email=email):
                if is_user_exists(username=username):
                    messages.info(request, 'Username is already taken.')
                else:
                    if is_valid_password(user_password):
                        if checkbox_value:
                            createUser = User.objects.create_user(first_name=first_name, last_name=last_name, username=username,
                                                              email=email)
                            createUser.set_password(user_password)
                            createUser.save()
                            return redirect('login')
                        else:
                            messages.info(request, 'Please accept the terms')
                    else:
                        messages.info(request, 'Create a strong password.')
            else:
                messages.info(request, 'Email is already registered.')
        except Exception as e:
            # Log the exception for debugging purposes
            logger.error(f"Error during user registration: {str(e)}")
            # Redirect to the error page
            return redirect('error')
            
    return render(request, 'register.html')


#------------------------------------- Service page -------------------------------------
@login_required(login_url='/error/')
def services(request):
    return render(request, 'service_page.html')
# ---------------------------------------EMIL VLIDAITION ----------------------------

def is_valid_email(email):
    """
    Validate an email address using Django's built-in email validation.

    Args:
    - email (str): The email address to be validated.

    Returns:
    - bool: True if the email is valid, False otherwise.
    """
    try:
        # Use Django's validate_email function
        validate_email(email)
        return True
    except ValidationError:
        # ValidationError will be raised if the email is not valid
        return False
    
# --------------------------  USER VALIDATION --------------------------------------

def is_user_exists(username):
    """
    Check if a user with the given username already exists.

    Args:
    - username (str): The username to check.

    Returns:
    - bool: True if the user exists, False otherwise.
    """
    return User.objects.filter(username=username).exists()

# --------------------------  PASSWORD VALIDATION --------------------------------------

def is_valid_password(password):
    """
    Validate a password using Django's built-in validators.

    Args:
    - password (str): The password to be validated.

    Returns:
    - bool: True if the password is valid, False otherwise.
    """
    # Use Django's built-in validators
    validators = [MinimumLengthValidator(), CommonPasswordValidator(), NumericPasswordValidator()]

    # Validate the password
    try:
        for validator in validators:
            validator.validate(password)
    except ValidationError as e:
        # If any validation fails, print the error message and return False
        print(e)
        return False

    # If all validations pass, return True
    return True

# ------------------------------- LOCK SCREEN ---------------------------------------

def lockscreen(request):
    logout(request)
    if request.method == 'POST':
        user_name = request.POST.get('username')
        user_password = request.POST.get('user-password')
        print(user_password, user_name)
        request.session['username'] = user_name
        # user authenticate
        user = authenticate(request, username=user_name, password=user_password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'lock-screen.html')

# ------------------------------- LOGOUT ---------------------------------------------

def userlogout(request):
    logout(request)
    return redirect('home')

# ------------------------------- USER PROFILE ----------------------------------------

@login_required()
def user_profile(request):
    first_letter = get_profile_first_img(request)
    # print(request.user.profile.profile_picture.url)

    # obj = Profile.objects.get(user=request.user)
    # pic = obj.profile_picture
    # print(pic)
    context = {
        "first_letter":first_letter+".png",
    }
    return render(request, 'user-profile.html',context)


def edit_profile(request):
    first_letter = get_profile_first_img(request)
    context = {
        "first_letter":first_letter+".png",
    }
    return render(request, 'edit-profile.html',context)

# ---------------------------- get profile name's first latter ------------------------------------------------
def get_profile_first_img(request):
    if request.user.is_authenticated:
        name = str(request.user)
        if name:
            # Get the first letter and capitalize it
            first_letter = name[0].capitalize()
    # Ignore the warning in this specific code block
    warnings.filterwarnings("ignore", message="When grouping with a length-1 list-like, you will need to pass a length-1 tuple to get_group in a future version of pandas.")
    return first_letter


# -------------------------------- Error page ----------------------------------------------------
def handler404_usermanagement(request):
    return render(request,"error_404.html")

# Create your views here.