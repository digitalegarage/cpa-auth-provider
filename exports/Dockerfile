FROM ubuntu:latest
MAINTAINER docker@ekito.fr

RUN apt-get update && apt-get -y install cron
RUN apt-get -y install postgresql-10

# Create the log file to be able to run tail
RUN touch /var/log/cron.log

ADD export.sh /export.sh
RUN chmod +x /export.sh

# Setup cron job
RUN (crontab -l ; echo "* * * * * /export.sh") | crontab

# Run the command on container startup
CMD cron && tail -f /var/log/cron.log
