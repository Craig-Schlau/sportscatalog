# Udacity Full Stack Nanodegree Project: Sports Catalog

# For this project the task is to create a repository to create, edit, deletes sports  and sports items.  This repository will allow a user to create a sport and create sport items for each sport he or she creates.  It will not allow user to edit or delete sports and sports items he or she does not create.
# This repository will allow the user to view sports and sports items in the database that were created by other users.
# This repository is a Python program connecting to the PostgresSQL database.

# This repository is hosted on Amazon Lightsail.
# Data will be obtained from a database named sportscatalog
# To load the data, access "http://18.218.24.9.xip.io" or "http://18.218.24.9.xip.io/sports"
# The data displayed is read only unless the user is logged in.

# This project implements a JSON endpoint at "http://18.218.24.9.xip.io/sports/JSON" and "http://18.218.24.9.xip.io/sports/<int:sports_id>/items/JSON"


## The submission file is named 'sportscatalog.zip" and includes the following files.
  * Source code: application.py
  * Static files:
      blank_user.gif
      styles.css
      top-banner.jpg
  * Template files:
      deleteSports.html
      deletesportsitems.html
      editSports.html
      editsportsitems.html
      header.html
      login.html
      main.html
      newSports.html
      newsportsitems.html
      publicsports.html
      sports.html
      sportsitems.html
  * client_secrets.json
  * database_setup
  * README.md

## To access the virtual machine, you must log in with ssh via command 'ssh grader@18.218.24.9 -p 2200 -i ~/.ssh/grader_key.pem' from the terminal window.

## To see the software components installed, please see the requirements.txt.

## All ports except 80(Application), 2200(SSH), and 123(NTP) are blocked at the firewall.

## The apache webserver uses sportscatalog.conf for the virtual host.

## Creator
* Craig Schlau
