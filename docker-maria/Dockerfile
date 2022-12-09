FROM mariadb:latest

# ------HERE you can set explicit DB root password or randomly created
# ENV MARIADB_RANDOM_ROOT_PASSWORD yes
ENV MARIADB_ROOT_PASSWORD ---FIXME---
# ------------

# ------HERE you can set DB name, user and password
ENV MARIADB_DATABASE sara
ENV MARIADB_RESCUER_USER rescuer
ENV MARIADB_RESCUER_PASSWORD ---FIXME---
# ------------

ADD a_createUsers.sh /docker-entrypoint-initdb.d/
ADD b_restoreModel.sql /docker-entrypoint-initdb.d/
ADD c_grant.sh /docker-entrypoint-initdb.d/
ADD d_exmapleData.sql /docker-entrypoint-initdb.d/

EXPOSE 3306

CMD ["--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci", "--max_connections=1000"]


# ------NOT DOCKER COMPOSE------
# ------USE FOR BUILDING AND RUNNING DOCKERIZED DB INSTANCE------
# docker build -t mariadb-server:latest .
# docker run -p 0.0.0.0:3306:3306 -d mariadb-server:latest
# ------------

