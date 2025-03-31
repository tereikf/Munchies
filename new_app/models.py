from database import db
from flask_login import UserMixin
from datetime import datetime, timezone

#intermediate association table for many-to-many follower and following relationship
followers_table = db.Table(
    'followers',
    db.Column('follower_id',db.Integer,db.ForeignKey('user.id',name = 'fk_follower_id'),primary_key=True),
    db.Column('followed_id',db.Integer,db.ForeignKey('user.id',name = 'fk_followed_id'),primary_key=True)
)

class User(db.Model, UserMixin):
    id= db.Column(db.Integer,primary_key=True)
    username= db.Column(db.String(150),unique=True,nullable=False)
    password= db.Column(db.String(255),nullable=False)
    email= db.Column(db.String(225),unique=True,nullable=False)
    bio= db.Column(db.String(225),nullable=True)
    profile_picture= db.Column(db.String(225),nullable=True)

    def __repr__(self):
        return f'<User: {self.username} Email: {self.email}>'
    def get_id(self):
        return self.id
    
    followers = db.relationship(
        "User",
        secondary=followers_table,
        primaryjoin=(followers_table.c.followed_id == id),
        secondaryjoin=(followers_table.c.follower_id == id),
        back_populates="following",
        lazy = "select"
    )

    following = db.relationship(
        "User",
        secondary=followers_table,
        primaryjoin=(followers_table.c.follower_id == id),
        secondaryjoin=(followers_table.c.followed_id == id),
        back_populates="followers",
        lazy = "select"
    )
    def follow(self,user): #follow user if not already following
        if not self.is_following(user):
            self.following.append(user)
            db.session.commit()

    def unfollow(self,user): #remove user from following column if there
        if self.is_following(user):
            self.following.remove(user)
            db.session.commit()

    def is_following(self,user):
        #check if user is already following the selected user
        return user in self.following




class Post(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    caption = db.Column(db.String(80),nullable=False)
    image_path = db.Column(db.String(500),nullable=False)
    description = db.Column(db.String(225),nullable=False)
    rating = db.Column(db.Integer,nullable=False)
    time_posted = db.Column(db.DateTime(timezone=True),default=datetime.now(timezone.utc))

    user = db.relationship('User',backref=db.backref("posts",lazy="joined"))
    comments = db.relationship('Comment',backref=db.backref("posts",lazy=True),cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    post_id = db.Column(db.Integer,db.ForeignKey('post.id'),nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)
    comment_text = db.Column(db.String(255),nullable = True)
    time_posted = db.Column(db.DateTime(timezone=True),default=datetime.now(timezone.utc))

    user = db.relationship('User',backref="comments")

    def __repr__(self):
        return f"<Comment {self.id} by User {self.user_id} on Post {self.post_id}"