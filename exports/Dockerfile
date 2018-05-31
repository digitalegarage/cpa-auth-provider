FROM java:openjdk-8-jdk

RUN apt-get -y update && apt-get install -y postgresql && apt-get clean && rm -rf /var/lib/apt/lists/*

# installing hadoop client
ENV HADOOP_VERSION 2.8.4
ENV HADOOP_URL http://www-eu.apache.org/dist/hadoop/common/hadoop-$HADOOP_VERSION/hadoop-$HADOOP_VERSION.tar.gz
RUN set -ex \
    && curl -fSL "$HADOOP_URL" -o /tmp/hadoop.tar.gz \
    && tar -xvf /tmp/hadoop.tar.gz -C /opt/ \
    && rm /tmp/hadoop.tar.gz*

ENV HADOOP_PREFIX=/opt/hadoop-$HADOOP_VERSION
ENV HADOOP_CONF_DIR=$HADOOP_PREFIX/etc/hadoop
ENV PATH $HADOOP_PREFIX/bin/:$PATH

ADD export.sh /export.sh
RUN chmod +x /export.sh

CMD ./export.sh
