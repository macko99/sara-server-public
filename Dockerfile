FROM debian:11

WORKDIR /app

# ------CHOOSE DB CONNECTION STRING------
# local db conf
ARG MARIADB_HOST=host.docker.internal
ARG MARIADB_DATABASE=sara
ARG MARIADB_RESCUER_USER=rescuer
ARG MARIADB_RESCUER_PASSWORD=---FIXME---
# online db (2nd one)
ENV MARIADB_URL mysql://$MARIADB_RESCUER_USER:$MARIADB_RESCUER_PASSWORD@$MARIADB_HOST/$MARIADB_DATABASE
#ENV MARIADB_URL mysql://---FIXME---


# ------FEEL FREE TO ADJUST------
ENV JWT_SECRET_KEY ---FIXME---
ENV PORT 5555
ENV HOST 0.0.0.0
ENV DEBUG True
ENV LOCALES PL
ENV CORS_ALLOWED_ORIGINS *
# sms & chat conf
ENV TWILIO_ACCOUNT_SID ---FIXME---
ENV TWILIO_API_KEY ---FIXME---
ENV TWILIO_API_SECRET ---FIXME---
ENV TWILIO_CHAT_SERVICE_SID ---FIXME---
ENV TWILIO_AUTH_TOKEN ---FIXME---
ENV TWILIO_SMS_SERVICE_SID ---FIXME---
ENV CHAT_ACTIVE True
ENV SMS_ACTIVE True
ENV SMS_SENDER_ID LOGIN
# apple push conf
ARG KEY_FILE=AuthKey_VRS64CBBFX.p8
ENV BUNDLE_ID com.lifeSavingApp
ENV KEY_ID ---FIXME---
ENV TEAM_ID ---FIXME---
ENV APN_SANDBOX False
ENV KEY_FILE $KEY_FILE
# ------------


COPY requirements.txt requirements.txt
COPY app.py app.py
COPY translations.py translations.py
COPY messaging.py messaging.py
COPY apple_push.py apple_push.py
COPY $KEY_FILE $KEY_FILE

RUN apt update -y && apt install -y python3-dev python3-pip default-libmysqlclient-dev build-essential
RUN pip3 install -r requirements.txt

EXPOSE 5555

ENTRYPOINT [ "python3", "app.py" ]


# ------NOT DOCKER COMPOSE------
# ------USE FOR BUILDING AND RUNNING DOCKERIZED SERVER APP------
# docker build -t flask-server:latest .
# docker run -p 5555:5555 -d flask-server:latest
# ------------