# Welcome to SARA project
#### Search and Rescue application

## iOS app repository: [🍎 iOS app](https://github.com/macko99/sara-ios)

## Docker compose repo: [💿 Docker](https://github.com/macko99/sara-docker)


## What's SARA?

SARA stands for Search and Rescue application

Praca inżynierska w ramach studiów I stopnia na Akademii Górniczo-Hutniczej w Krakowie na kierunku Informatyka 

Zadaniem aplikacji jest monitorowanie, koordynowanie i zarządzanie w czasie rzeczywistym poszukiwawczymi w różnych terenach. Aplikacja będzie umożliwiała śledzenie ruchów grup, pokrytego przez nią terenu oraz komunikację dwustronną z centralą oraz grupami między sobą, wraz z przesyłaniem zdjęć i plików.

## Contributors

- <a href="https://github.com/tombush0">Tomasz Zachwieja</a>
- <a href="https://github.com/macko99">Maciej Kozub</a>

## About this repository

1. This repository is maintained for Heroku app deployment as well as for Docker images of server side application and database
2. Application is available at: https://sara-server.herokuapp.com
3. Autodeployment is done for branch **heroku-online-version**
4. This application provides REST API for mobile and web clients
5. Web client for this API is available at: https://sara-panel.herokuapp.com

---
### UPDATE 🧑🏻‍💻
[Docker Compose](https://docs.docker.com/compose/) images prepared 

Now you are just one command away from running **database + backend + frontend** locally

1. Make sure you have [Docker](https://www.docker.com/get-started) installed on your system

2. **Increase RAM allocation for docker (e.g. using Docker Desktop) to at least 4GB**

3. Clone [💿 Docker](https://github.com/macko99/sara-docker) and navigate to folder **docker**, you will find **docker-compose.yaml** inside

4. Execute 

        $ docker compose up -d --build

5. All info below about running seperate docker images are still valid

6. For more information and adjustments please read comments inside **docker-compose.yaml** and proper **Dockerfiles**

---

## Running Dockerized server application

1. Make sure you have [Docker](https://www.docker.com/get-started) installed on your system

2. Run two commented commands from **Dockerfile**:

        $ docker build -t flask-server:latest .
        $ docker run -p 5555:5555 -d flask-server:latest

3. For use with locally Dockerized database please look inside **Dockerfile**

## Running Dockerized database instance

1. Make sure you have [Docker](https://www.docker.com/get-started) installed on your system

2. Enter **docker/docker-maria** folder in system terminal 

        $ cd docker-flask

3. Run two commented commands from **Dockerfile**:

        $ docker build -t mariadb-server:latest .
        $ docker run -p 0.0.0.0:3306:3306 -d mariadb-server:latest

4. For use with locally Dockerized database please look inside **Dockerfile**

## Testing API

1. Please import `sara.postman_collection.json`  and/or `sara-heroku.postman_collection.json` collection to [Postman](https://www.postman.com/) (File->Import)

2. Test users already in DB:
- maciek, password: maciek
- admin, password: 4yntM5TJC9azuUbU

## Local development

1. (Recommended) Create Python virtual enviroment by yourself or let it be set up by your Python IDE (e.g. PyCharm):

        $ bin/virtualenv sara-server
        $ source bin/activate

2. Install required python packages:

        $ pip install -r requirements.txt

3. Set proper environment variables available to **app.py** python runtime:

   - DEBUG=True
   - JWT_SECRET_KEY=...
   - MARIADB_URL=...
   - ...


4. Run* `app.py` using your Python IDE play button or by executing:

        $ python3 app.py

    *tested using **Python 3.9**

5. Find your computer IP address (on MacOS press on Wi-Fi icon on top bar while pressing Option key) or execute:

        $ ipconfig getifaddr en0

      local instance of server is by default bind to port **5555**

6. Found a bug? Please report Issue on GitHub

## Deployment on Heroku

1. Install [Heroku CLI](https://devcenter.heroku.com/articles/getting-started-with-python#set-up)

2. To deploy changes:

        git push heroku master

3. See logs:

        heroku logs --tail

4. Scale your application:

        heroku ps:scale web={number}

5. Run any commend in enviroment (inpersistent):

        heroku run {command}

## SQLAlchemy usage

1. Initialize database based on defined model:

        flask db init

2. Create model migration:

        flask db migrate -m "<migration description>"    

3. Appeal migration and update db:

        flask db upgrade

---

## How to make it work?

Fix all `---FIXME---` placeholders in the source code.