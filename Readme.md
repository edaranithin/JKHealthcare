python.exe -m venv venv
venv/Scripts/activate
pip install -r requirements.txt
set FLASK_APP=app.py
flask create_admin
python app.py



**************************
username - admin
password - admin