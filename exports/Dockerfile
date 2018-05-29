FROM ubuntu:latest
MAINTAINER docker@ekito.fr

RUN apt-get update && apt-get -y install postgresql-10

ADD export.sh /export.sh
RUN chmod +x /export.sh

CMD ./export.sh
