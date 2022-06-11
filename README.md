# Flask Login

This project is using free responsive UI from [Colorlib](https://colorlib.com/wp/template/login-form-06/), using Flask  with SQLAlchemy and Google API to send email & login 

Please create new project with Credentials (OAuth Client ID) in purpose of getting json creadentials for this project

You can check this [link](https://developers.google.com/workspace/guides/create-credentials) to see how to create new Credential for Google project

Reference for [Gmail Login](https://github.com/code-specialist/flask_google_login), [Gmail Email](https://learndataanalysis.org/how-to-use-gmail-api-to-send-an-email-in-python/)

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar, this project using Python3.7
You can install packages through `requirements.txt`

```bash
pip install -r requirements.txt
```

## Run a project

```python
python3 app.py
```

## Note
You have to set Email port different with Project port then 


`Authorized redirect URIs` on Google Console should have to declare local URI with port 5500 (as example for this porject )

```python
http://127.0.0.1:5000/gCallback
http://127.0.0.1:5500/
```
 

Please contact when you get any issues: `tranvinhliem1307@gmail.com`

-----------------------------------> [Demo](https://login-test.cloudbits.site/login) <-----------------------------------
