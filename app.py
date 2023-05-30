from flask import Flask,render_template,request,session,flash,redirect,url_for
from flask_mysqldb import MySQL
import requests
from requests.auth import HTTPBasicAuth
import re
import json

consumer_key='8SpRvUoz4pr9d5aCZ4Fx2G3jZn80DVIh'
consumer_secret='9pgoapUfAttNaqBR'
base_url = 'http:127.0.0.1:5000'


app=Flask(__name__)
app.secret_key='layton'

app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']=''
app.config['MYSQL_DB']='ecormmerce'

mysql=MySQL(app)

@app.route('/register',methods=['POST','GET'])
def register():
    if 'username'in session:
        flash(f"You have already registered as {session['username']}",'info')
        return redirect(url_for('home'))
    else:
        if request.method=='POST':
            username=request.form['username']
            email=request.form['email']
            password=request.form['password']
            confirm=request.form['confirm']
            if username==''or email==''or password==''or confirm=='':
                flash('All fields are required','danger')
                return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
            elif password!=confirm:
                flash('Passwords do not match','danger')
                return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
            elif len(password)<8:
                flash('Password should be more than 8 characters','danger')
                return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
            elif not re.search("[a-z]",password):
                flash('Password should contain small letters','danger')
                return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
            elif not re.search("[A-Z]", password):
                flash('Password should contain capital letters','danger')
                return render_template('register.html',username=username,email=email,password=password,confirm=confirm)
            else:
                cur=mysql.connection.cursor()
                cur.execute("INSERT INTO users(username,email,password)VALUES(%s,%s,%s)",(username,email,password))
                mysql.connection.commit()
                cur.close()
                flash(f"Account created  for {username}",'success')
                return redirect(url_for('login'))
        return render_template('register.html')


@app.route('/login',methods=['POST','GET'])
def login():
    if 'username'in session:
        flash(f"You are already logged in as {session['username']}",'info')
        return redirect(url_for('home'))
    else:
        if request.method=='POST':
            username=request.form['username']
            password=request.form['password']

            cur=mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username=%s AND password=%s",(username,password))
            mysql.connection.commit()
            user=cur.fetchone()
            cur.close()
            if user is not None:
                session['loggedin']=True
                session['username']=user[1]
                session['user_id']=user[0]
                flash(f"You are logged in as {username} now you can shop with us",'success')
                return redirect(url_for('payment'))
            else:
                flash('Wrong credentials','danger')
                return render_template('login.html',username=username,password=password)
        return render_template('login.html')

@app.route('/profile', methods=['POST','GET'])
def profile():
    if 'username' in session:
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM users")
        mysql.connection.commit()
        user=cur.fetchall()
        cur.close()
        for data in user:
            username=data[1]
            email=data[2]
            return render_template('profile.html',username=username,email=email)
        
    if request.method=='POST':
        address=request.form['address']
        address2=request.form['address2']
        city=request.form['city']
        state=request.form['state']
        zipcode=request.form['zip']
        user_id=session['user_id']
        cur=mysql.connection.cursor()
        cur.execute("UPDATE users SET address=%s,address2=%s,city=%s,state=%s,zipcode=%s WHERE id=%s",(address,adress2,city,state,zipcode,user_id,))
        mysql.connection.commit()
        cur.close()
        flash('Details successfully updated','success')
        return render_template('profile.html')
    

    return render_template('profile.html')        


@app.route('/cart/<id>')
def cart(id):
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM shoes WHERE id=%s",(id,))
    shoes=cur.fetchall()
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM men WHERE id=%s",(id,))
    data=cur.fetchall()
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM menshoes WHERE id=%s",(id,))
    menshoes=cur.fetchall()
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM womenbags WHERE id=%s",(id,))
    bag=cur.fetchall()
    
    return render_template('cart.html',output=shoes )


@app.route('/access_token')
def token():
    data=ac_token()
    return data
    

@app.route('/register_urls')

def newrls():

    mpesa_endpoint=""

    headers={ "Authorization":"Bearer %s" % ac_token() }

    req_body={
        "ShortCode":"600383",
        "ResponseType":"Completed",
        "ConfirmationURL": base_url + "c2b/confirm",
        "ValidationURL":base_url + "c2b/confirm"
    }

    response_data = requests.post(
    mpesa_endpoint,
    json=req_body,
    headers = headers
    )
         
    return response_data


@app.route('/c2b/confirm')
def confirm():
    data = request.get_json()
    file = open('confirm.json','a')
    file.write(data)
    file.close()


@app.route('/c2b/validation')
def validate():
    data = request.get_json()
    file = open('confirm.json','a')
    file.write(data)
    file.close()
   


def ac_token():
    mpesa_auth_url='https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'

    data=(requests.get(mpesa_auth_url,auth=HTTPBasicAuth(consumer_key, consumer_secret))).json()
    return data['access_token']
    

@app.route('/payment')
def payment():
    
    return render_template('pay.html')


@app.route('/contact')
def contact():
    if 'username' not in session:
        flash('To contact us you MUST  login','info')
        return redirect(url_for('login'))
    else:
        return render_template('contact.html')
    return render_template('contact.html')

@app.route('/')
def home():
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM shoes")
    shoes=cur.fetchall()
    cur.execute("SELECT * FROM men")
    data=cur.fetchall()
    cur.execute("SELECT * FROM menshoes")
    menshoes=cur.fetchall()
    cur.execute("SELECT * FROM womenbags")
    bags=cur.fetchall()
    mysql.connection.commit()
    cur.close()
    return render_template('home.html',shoes=shoes,data=data,menshoes=menshoes,bags=bags)




@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('loggedin',None)
        session.pop('username',None)
        flash('You have been logged out','info')
    return redirect(url_for('home'))

if __name__=='__main__':
    app.run(debug=True)



""" if 'username' not in session:
        flash('To make payments yo MUST login','info')
        return redirect(url_for('login'))
    else:
        return render_template('pay.html') """