from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import User
import bcrypt

# Create your views here.

def index(request):
    if 'logged_in' in request.session:
        if request.session['logged_in'] == True:
            user = User.objects.get(id=request.session['id'])
            if user.email != request.session['email']:
                request.session.clear()
                request.session.modified = True
                return render(request, 'login_and_registration/index.html')
            else:
                return render(request, 'login_and_registration/index.html', { "user": User.objects.get(id=user.id) } )
        else:
            return render(request, 'login_and_registration/index.html')
    else:
        return render(request, 'login_and_registration/index.html')

def create(request):
    errors = User.objects.basic_validator(request.POST)
    if len(errors):
        for key, value in errors.items():
            messages.error(request, value)
        return redirect('/')
    else:
        user = User.objects.create()
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.email = request.POST['email']
        user.password = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user.save()
        request.session['new_registration'] = True
        request.session['id'] = user.id
        request.session['email'] = user.email
        return redirect("/login/success")

def validate_login(request):
    users = User.objects.all()
    try:
        user = users.get(email=request.POST['email'])
        if bcrypt.checkpw(request.POST['password'].encode(), user.password.encode()):
            request.session['logged_in'] = True
            request.session['id'] = user.id
            request.session['email'] = user.email
            if 'new_registration' in request.session:
                del request.session['new_registration']
                request.session.modified = True
            return redirect('/login/success')
        else:
            messages.error(request, "Invalid password!")
            return redirect('/')
    except User.DoesNotExist:
        messages.error(request, "Email does not exist! Please register to continue")
        return redirect('/')

def success(request):
    if 'new_registration' in request.session:
        request.session['logged_in'] = True
        user = User.objects.get(id=request.session['id'])        
        return render(request, 'login_and_registration/success.html', { "user": User.objects.get(id=user.id) })
    elif 'logged_in' in request.session:
        if request.session['logged_in'] == True:
            user = User.objects.get(id=request.session['id'])
            if user.email != request.session['email']:
                request.session.clear()
                return render(request, 'login_and_registration/success.html')
            else:
                return render(request, 'login_and_registration/success.html', { "user": User.objects.get(id=user.id) } )
        else:
            return render(request, 'login_and_registration/success.html')
    else:
        return render(request, 'login_and_registration/success.html')

def logout(request):
    request.session.clear()
    request.session.modified = True
    return redirect('/')