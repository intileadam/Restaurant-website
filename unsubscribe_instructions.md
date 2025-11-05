# DreamHost Deployment — Unsubscribe Service (Passenger)


> This section walks you through hosting the **unsubscribe microservice** on DreamHost using **Passenger** on a subdomain like `unsubscribe.casadelpollo.com`. Your main site can remain static on `casadelpollo.com`.


## 0) Prereqs
- DreamHost shared/VPS account with shell (SSH) access.
- Your DreamHost user (e.g., `dhuser`) and domain already added in the panel.
- MySQL database created in DreamHost panel (note your **DB host** e.g., `mysql.casadelpollo.com`, DB name, user, and password).


## 1) Add a subdomain for the app
1. DreamHost Panel → **Websites** → **Manage Websites** → **Add Hosting to a Domain / Sub-Domain**.
2. Enter `unsubscribe.casadelpollo.com`.
3. Check **Passenger (Ruby/NodeJS/Python apps)** (a.k.a. "Enable Passenger").
4. Enable **Let’s Encrypt** (HTTPS).
5. Save.


> DreamHost will create a directory like: `/home/dhuser/unsubscribe.casadelpollo.com/`


## 2) Deploy the app files
On your machine, copy this subset of the repo to the subdomain directory (via `scp` or SFTP):

├─ server.py # Flask microservice for casadelpollo.com
│ └─ templates/
│ ├─ unsubscribed.html
│ └─ error.html

### `passenger_wsgi.py`
```python
# passenger_wsgi.py — DreamHost/Passenger entrypoint
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from unsubscribe_service.server import app as application


### requirements.txt
Flask==3.0.2
python-dotenv==1.0.1
mysql-connector-python==9.0.0


### Create a virtualenv & install deps (over SSH)
ssh dhuser@dreamhost.com # or the server your user lives on
cd ~/unsubscribe.casadelpollo.com
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

### Create /home/dhuser/unsubscribe.casadelpollo.com/.env with your production DB settings (do not commit this file):
DB_HOST=mysql.casadelpollo.com # your DreamHost MySQL hostname
DB_PORT=3306
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_NAME=restaurant_db

### Restart Passenger
mkdir -p tmp
touch tmp/restart.txt


### Test it
https://unsubscribe.casadelpollo.com/unsubscribe?token=TEST


### Point your emails at the subdomain
BASE_URL_PUBLIC=https://unsubscribe.casadelpollo.com
UNSUBSCRIBE_PATH=/unsubscribe

### Health check
https://unsubscribe.casadelpollo.com/healthz
