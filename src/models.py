from app import db

class Account(db.Model):
    __tablename__ = 'accounts'
    
    id          = db.Column(db.Integer, primary_key=True)
    public_id   = db.Column(db.String(50), unique = True)
    uname       = db.Column(db.String, unique=True, nullable=False)
    passwd      = db.Column(db.String, nullable=False)
    name        =  db.Column(db.String, nullable=False)
    email        = db.Column(db.String, unique=True, nullable=False)
    ref_code    = db.Column(db.String)
    
    def __init__(self, public_id, uname, passwd, name, email, ref_code):
        self.public_id = public_id
        self.uname = uname
        self.passwd = passwd
        self.name = name
        self.email = email
        self.ref_code = ref_code

    # membuat mothod untuk menyimpan data agar lebih simple
    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
            return True
        except:
            return False
