# Invinsense CSPM

## Description

-Invinsense CSPM is a security tool designed for AWS (Amazon Web Services) environments.
It is a security best practices assessment, auditing, and hardening framework for AWS accounts.

- CSPM is created on Django version 5.0.2 (06 Feb 2024)
  

## Instalation

- Download or clone the repo in your local system.
- After the clone repo you need to install the necessary requirnments.
- for that run belowe command
  ### pip install -r requirements.txt

- After installing the dependency you need to run the following commands

  ### python manage.py makemigrations
  ### python manage.py migrate

- this command will migrate the database file with your project
- Now the system is ready to run.

- For run the **CSPM** you need to execute belowe command.

  ### python manage.py runserver

- This command will create a link in your terminal just click on that link with press the **ctrl** key
- You will redirect to the your system's default browser.

- You will be redirected on the landing page. On that page you need to register a new user after registration you will redirect on the Service page
- in which you can choose the service you want to.

- Right now in this case the **AWS** is perfecty working other services are in development phase so you need to select **AWS**.

- Then you will directed on the Dashboard in which you need to integrate your cloud account first and then you will able to scan the cloud.  


