# Item Catalog

The objective of the Item Catalog is to build a website with Flask, SQLAlchemy, third party OAuths and API endpoints.

## How to run ?

### 1. Setup: Configure VM & Database

**Step 1:** Download and install [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org). We require these to setup and manage the Virtual Machine (VM).

**Step 2:** After cloning the project, open the terminal and then run the following commands:

```
# Install & Configure VM
cd /path/to/vagrant
vagrant up

Note: First time it will take time to install ubuntu

# Log into machine
vagrant ssh
```

**Step 3:**

```
Get client ID from google (https://console.developers.google.com/)

Edit "client_secrets.json"file and replace client_id,client_secret and project_id with yours

Here are the contents of the file

{
"web": {
"client_id": "757993430840-eq5qkimop73tdglvm36qb97lkhjolnl6.apps.googleusercontent.com",
"project_id": "udacity-214211",
"auth_uri": "https://accounts.google.com/o/oauth2/auth",
"token_uri": "https://www.googleapis.com/oauth2/v3/token",
"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
"client_secret": "drUwRs8_yPzwtqNYGRVIdTq7",
"redirect_uris": ["http://localhost:5000"],
"javascript_origins": ["http://localhost:5000"]
}
}


Note - For more information visit https://developers.google.com/identity/protocols/OAuth2
```

**Step 4:**
Run the website

Open the terminal. Then, run the following commands:

```
# Launch & Login to machine

cd /path/to/vagrant
vagrant up
vagrant ssh

# Open shared folder

cd /vagrant/catalog

# Setup Database

python database_setup.py

# Run the program

python application.py
```

**Step 5:**
Access using http://localhost:5000/
