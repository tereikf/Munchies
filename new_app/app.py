from flask import Flask,request,Response,send_from_directory,session,make_response, \
redirect,make_response,render_template,url_for,jsonify,get_flashed_messages,flash
import pandas as pd
import openpyxl, os,uuid
from database import db
import urllib.parse
from models import User,Post, Comment
from flask_migrate import Migrate
from flask_login import LoginManager,logout_user,login_required,login_user,current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import check_password_hash
from flask_mail import Mail, Message
from support import validate_password
from werkzeug.utils import secure_filename

app = Flask(__name__,template_folder='templates',static_folder='static',static_url_path='/')
app.secret_key = 'SOMETHING CRYPTIC'

db_password = urllib.parse.quote("Unl1m1t3d!")
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://postgres:{db_password}@127.0.0.1:5555/projectdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

with app.app_context():
    #db.drop_all()
    db.create_all()
 
migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

bcrypt = Bcrypt(app)

#email configuration

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORRT'] = 587
app.config['MAIL_USE_TLS'] = True
#app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'tereikfaulknor@gmail.com'
app.config['MAIL_PASSWORD'] = 'fzai kmkd qary pjgj'
app.config['MAIL_DEFAULT_SENDER'] = ('Flask App','tereikfaulknor@gmail.com')
mail = Mail(app)
mail.init_app(app)

#upload content config
UPLOAD_FOLDER = 'static/uploads/'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

allowed_extensions = {'png','jpeg','jpg'}

#profile picture directory
if not os.path.exists('static/profile_pics'):
    os.makedirs('static/profile_pics')

#checking if file is valid in terms of extension
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in allowed_extensions

@app.route('/',methods=['GET','POST']) 
def index():


    
    return render_template('index_2.html',message='Index',user=current_user)


"""Manipulating Sessions which is data stored on the server side, cannot be changed by user"""
@app.route('/set_data')
def set_data():
    session['name'] = 'BigT'
    session['other'] = 'Whattup'

    return render_template('index_2.html',message='Session data sucessfully set',user=current_user)

@app.route('/get_data')
def get_data():
    if 'name' in session.keys() and 'other' in session.keys():
        name = session['name']
        other = session['other']

        return render_template('index_2.html',message=f'Name:{name},Other:{other}',user=current_user)
    else:
        return render_template('index_2.html',message='No Session Found',user=current_user)
    
@app.route('/clear_session')
def clear_session():
    session.clear()
    return render_template('index_2.html',message='Session Cleared',user=current_user)

'''Users can manipulate cookies through the client side'''

@app.route('/set_cookie')
def set_cookie():
    response = make_response(render_template('index_2.html',message='Cookie set',user=current_user))
    response.set_cookie('cookie_name','cookie_value')

    return response

@app.route('/get_cookie')
def get_cookie():
    cookie_value = request.cookies['cookie_name']

    return render_template('index_2.html',message=f'Cookie value: {cookie_value}')

@app.route('/remove_cookie')
def remove_cookie():
    #create a response to expire the cookie
    response = make_response(render_template('index_2.html',message='Cookie removed',user=current_user))
    response.set_cookie('cookie_name',expires=0)

    return response

@app.route('/sign-up',methods=['GET','POST'])
def sign_up():
    if request.method == 'GET':
        return render_template('sign-up.html')
    else:
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        email = request.form.get('email')
        id = request.form.get('id')

        if not username or not password1 or not password2 or not email:
            flash('All fields are required!','warning')
            return redirect(url_for('sign_up'))

        valid,message,category = validate_password(password1,password2)
        if not valid and message:
            flash(message,category)
            return redirect(url_for('sign_up'))
        password = password1
                 
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('This username already exists!','error')
            return redirect(url_for('sign_up'))
            
        try:
            if username and password:
                
                #send user confirmation email
                send_confirmation_email(username,email)
                flash('User account created successfully!','success')

                #encrypt password
                hashed_pword = bcrypt.generate_password_hash(password).decode('utf-8')

                #create user object and user profile object, commit to db
                new_user =User(id=id,username=username,password=hashed_pword,email=email)
                db.session.add(new_user)
                db.session.commit()

                return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user {e}','error')
            return redirect(url_for('sign_up'))
        
    return redirect(url_for('login'))
            



@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html',user=current_user)
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        id = request.form.get('id')

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login Successful','success')
            return redirect(url_for('profile',username=user.username))
        else:
            flash('Incorrect username or password',category="error")
            return render_template('login.html',message='',user=current_user)

@app.route('/logout',methods=['GET'])
@login_required
def logout(): 
    logout_user()
    return redirect(url_for('index'))



@app.route('/profile/<username>',methods=['GET'])
@login_required
def profile(username):
    try:
        selected_user = User.query.filter_by(username=username).first()
        flash(f'Selected user: {selected_user}') #debugging
        if selected_user == current_user:
            return render_template('profile.html',user=selected_user,posts=selected_user.posts)
        else:
            return render_template('view-profile.html',user=current_user,selected_user=selected_user,posts=selected_user.posts)
    except Exception as e:
        db.session.rollback()
        flash(f'Error retrieving profile: {e}','error')
        return redirect(url_for('index'))
    

@app.route('/edit-profile',methods=['GET','POST'])
@login_required
def edit_profile():
    #retrieve user information and display edit profile form
    if request.method == 'GET':
        user = User.query.filter_by(id = current_user.id).first()
        return render_template('edit-profile.html',user=user,message='')
    else:
        try:
            user = User.query.filter_by(id = current_user.id).first()

            #retrieve profile picture file from form if it exists
            
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']

                if file.filename != '' and allowed_file(file.filename): #checks if image file is of the correct type
                    filename = secure_filename(file.filename)
                    path = os.path.join('static/profile_pics',filename)
                    file.save(path)  #save image to configured path
                    profile_picture = str(filename)
                    print(type(profile_picture))
                    user.profile_picture = profile_picture

            print(f"Before assignment, user.profile_picture: {user.profile_picture}, type: {type(user.profile_picture)}")
            user.bio = request.form.get('bio')
            db.session.commit()

            flash('Profile updated successfully!','success')
            return redirect(url_for('profile',username=current_user.username))

        except Exception as e:
            db.session.rollback()
            flash(f'Error editing profile {e}')
            return redirect(request.url)

@app.route('/change_password',methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'GET':
        return render_template('change-password.html',user=current_user)
    else:

        try:
            user = current_user
            current_pword = request.form.get('password')
            user = User.query.filter_by(username=user.username).first()
            if bcrypt.check_password_hash(user.password,current_pword):
                subject = "Password Change Request"

                recipient = user.email
                #link = url_for('reset_password',_external=True)
                body = f"""
Hello {user.username}

To change your password, follow the embedded link
{url_for('reset_password',_external=True)}

- Flask Team
"""

                msg = Message(subject,recipients=[recipient],body=body)
                mail.send(msg)
                flash('The reset link has been sent to your email','info')
            
                return render_template('change-password.html',user=current_user)
            
            else:
                flash('The password entered is incorrect!','error')
                return render_template('change-password.html',user=current_user)           
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user {e}','error')
    return render_template('change-password.html',user=current_user)

@app.route('/reset-password',methods=['GET','POST'])
@login_required
def reset_password():
    if request.method == 'GET':
        return render_template('reset-password.html',user=current_user)
    else:
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')


        valid, message,category = validate_password(password1,password2)
        if valid:
            new_password = password1
            if bcrypt.check_password_hash(current_user.password,new_password):
                flash('New password cannot be same as the pre-existing password!',category=category)
                return render_template('reset-password.html',user=current_user)
            else:
                hashed_password = bcrypt.generate_password_hash(new_password)
                current_user.password = hashed_password
                db.session.commit()
                flash('Password changed successfully',category=category)
                return redirect(url_for('profile',username=current_user.username))
        else:
            flash(message,category=category)
            return render_template('reset-password.html',user=current_user)

@app.route('/upload_profile_pic',methods=['GET','POST'])
@login_required
def upload_profile_pic():
    return ''


@app.route('/feed',methods=['GET'])
@login_required
def feed():
    return render_template('feed.html',message='',user=current_user,posts=Post.query.all())


#retrieves data from the form to add to the database as a user post
@app.route('/post',methods=['GET','POST'])
@login_required
def create_post():
    if request.method == 'GET':
        return render_template('create-post.html',message='',user=current_user)
    else:
        try:
            #for encrypting the filename


            caption = request.form.get('caption')
            description = request.form.get('description')
            rating = request.form.get('rating')
            user_id = current_user.id

            if int(rating) > 5 or int(rating) < 1:
                raise Exception('Rating must be between 1 and 5 inclusive')

            print(request.form)
            print(request.files)

            #handling post image edge cases
            if 'image' not in request.files:
                flash('No image found','error')
                return redirect(request.url) 
            image = request.files['image']

            if image.filename == '':
                flash('No valid image selected','error')
                return redirect(request.url) 
               
            if not allowed_file(image.filename):
                flash('The allowed extensions are: .png, .jpg and .jpeg','error')
                return redirect(request.url)
        
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            image_path = filename

            #create a new post object to store in table
            new_post = Post(user_id=user_id,caption=caption,image_path=image_path,description=description,rating=rating)
            
            db.session.add(new_post)
            db.session.commit()
            #post added to db
            flash('Post made successfully','success')
            flash(f'<Post created at {new_post.time_posted}>','info')
            return redirect(url_for('feed'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating post: {e}','error')
            return render_template('create-post.html',message='Post failed',user=current_user)
        
#comment on user post
@app.route('/<post_id>/comment',methods = ['POST'])
@login_required
def comment(post_id):
    try:
        selected_post = Post.query.filter_by(id = post_id).first()
        comment_text = request.form.get('comment_text')
        new_comment = Comment(post_id=post_id,user_id = selected_post.user.id,comment_text=comment_text)
        db.session.add(new_comment)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Error making comment: {e}','error')
        return redirect(url_for('user_posts',post_id=post_id))
        
#allow user to follow another user
@app.route('/follow/<username>',methods=['POST'])
@login_required
def follow(username):
    try:
        selected_user = User.query.filter_by(username=username).first()

        if not selected_user:
            flash('User not found','danger')
            return redirect(url_for('feed'))
        
        if not current_user.is_following(selected_user):
            current_user.follow(selected_user)
            flash(f'You are now following {username}','success')
            return redirect(url_for('profile',username=username))
    except Exception as e:  
        db.session.rollback()
        flash(f'Error following user: {e}','error')
        return redirect(url_for('profile',username=username))


@app.route('/unfollow/<username>',methods=['POST'])
@login_required
def unfollow(username):
    try:
        selected_user = User.query.filter_by(username=username).first()

        if not selected_user:
            flash('User not found','danger')
            return redirect(url_for('feed'))
        
        if current_user.is_following(selected_user):
            current_user.unfollow(selected_user)
            flash(f'Unfollowed {username}','success')
            return redirect(url_for('profile',username=username))
    except Exception as e:  
        db.session.rollback()
        flash(f'Error following user: {e}','error')
        return redirect(url_for('profile',username=username))

#allow user to delete their post

@app.route('/delete-post/<int:post_id>',methods=['POST'])
@login_required
def delete_post(post_id):
    try:
        selected_post = Post.query.filter_by(id = post_id).first()
        db.session.delete(selected_post)
        db.session.commit()
        posts = Post.query.filter_by(user_id = current_user.id)
        return redirect(url_for('profile',message='Post deleted successfully!',user=current_user,posts=posts,
                                username=current_user.username))

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting post: {e}','error')
        return redirect(request.url)
    
#select specific post in timeline
@app.route('/feed/post.id',methods=['GET'])
def user_posts():
    try:
        post_id = request.args.get('post_id')
        selected_post = Post.query.filter_by(id = post_id).first()
        return render_template('post.html',message='',user=current_user,post=selected_post,comments=selected_post.comments)
    except Exception as e:
        db.session.rollback()
        flash(f'Error retrieving post: {e}','error')
        return redirect(request.url)


@app.route('/clear')
def clear_users():
    User.query.delete()
    db.session.commit()

    return render_template('index_2.html',user=current_user)


@app.route('/send_confirmation_email', methods=['GET'])
def send_confirmation_email(username,email):
    subject = "Welcome to Munchies"

    recipient = email

    body = f"""
    Hello {username},

    Thank you for signing up for Munchies.

    Best,
    Munchies Team
    """
    
    msg = Message(subject,recipients=[recipient],body=body)
    mail.send(msg)

#template filters

@app.template_filter('star')
def star(rating):
    return rating * "⭐"

@app.template_filter('format_time')
def format_time(posted_time):
    from datetime import datetime
    return posted_time.strftime('%Y-%m-%d %H:%M')
    

if __name__ == '__main__':
    app.run('0.0.0.0',5000,debug=True)
'''

@app.route('/file_upload',methods=['POST'])
def file_upload():
    file = request.files['file']
    
    if file.content_type == 'text/plain':
        return file.read().decode()

    elif file.content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' or \
    file.content_type == 'application/vnd.ms-excel':
        df = pd.read_excel(file)
        return df.to_html()
    

#allowing excel to csv file conversion and allow download


#FIRST WAY, IMMEDIATELY RETURNS DOWNLOADED FILE AS RESPONSE
@app.route('/convert_csv',methods=['POST'])
def convert_csv():
    file = request.files['file']

    df = pd.read_excel(file)


    response = Response(
        df.to_csv(),
        mimetype='text/csv',
        headers={
            'Content-Disposition':'attachment; filename=result.csv'
        }
    )
    return response


#More professional way, uses download page

@app.route('/convert_csv_2',methods=['POST'])
def convert_csv_2():
    file = request.files['file']
    df = pd.read_excel(file)

    if not os.path.exists('downloads'):
        os.makedirs('downloads')

    filename = f'{uuid.uuid4()}.csv'
    df.to_csv(os.path.join('downloads',filename))

    return render_template('downloads.html',filename=filename,user=current_user)

@app.route('/downloads/<filename>')
def download(filename):
    return send_from_directory(directory='downloads',path=filename,download_name='result.csv')


@app.route('/handle_post',methods=['POST'])
def handle_post():
    greeting = request.json['greeting']
    name = request.json['name']

    with open('file.txt','w') as file:
        file.write(f'{greeting},{name}')

    return jsonify({'message':'Successfully written'})

@app.route('/<name>/hello', methods = ['GET','POST'])
def hello(name):
    if request.method == 'GET':
        return 'you made a get request\n'
    elif request.method == 'POST':
        return 'you made a post request\n'

    response = make_response(f'Hello {name}\n')
    response.status_code = 202
    response.headers['content-type'] = 'text/plain'
    return response


@app.route('/add/<int:num1>/<int:num2>') #dynamic URLS
def add(num1,num2):

    return f'{num1} + {num2} = {num1+num2}'

@app.route('/handle_url_params')
def handle_params():
    if 'greeting' in request.args.keys() and 'name' in request.args.keys():

        greeting = request.args['greeting']
        name = request.args['name']
        return f'{greeting}, {name}'
    else:
        return 'parameters are missing'
    
@app.route('/other')
def other():
    text = "whattup my chiggga"
    return render_template('other.html',text=text)

@app.route('/redirect_endpoint')
def redirect_endpoint():
    return redirect(url_for('other'))

@app.template_filter('reverse_string') #able to make custom filters for templates
def reverse_string(s):
    return s[::-1]

@app.template_filter('repeat_string')
def repeat_string(s,times):
    return (s+" ") * times

@app.template_filter('alternate_casing')
def alternate_casing(s):
    return "".join([s[i].upper() if i % 2 == 0 else s[i].lower() for i in range(len(s))])

'''
