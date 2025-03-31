

def validate_password(password1, password2):
    if password1 == password2:
        password = password1
    else:
        return (False,"Passwords do not match!",'error')
    
    
    if len(password) < 6:
        return (False,"Password must be at least 6 characters long",'warning')
    elif not any(letter.isupper() for letter in password):
        return (False,"Password must have at least 1 uppercase character",'warning')
    elif not any(char in '~!@#$%^&*(),.?' for char in password):
        return (False,"Password must have at least 1 valid special character",'warning')
    return (True,None,'success')

