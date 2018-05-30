# Exports

Export sub project provide a container that periodically exports data from IDP database into a CSV file and push it into a specified HDFS.

# Tests

To run export locally you might have to checkout [pipe-hadoop project](https://git.ebu.io/pipe/pipe-hadoop) and to build docker image using following commands:

```
cd pipe/pipe-hadoop/pipe-hadoop/
docker build -t local/pipe-hadoop .
```

Then start test containers by running 

```
docker-compose up -d --build
```

To view the extracted file

```
docker-compose exec exporter bash
more export.csv
```

Should display a csv like the following

```
user_id,year_of_birth,haslocalaccount,isfacebookaccountlinked,isgoogleaccountlinked,haslocalaccount,isemailaddressverfied,gender,language,last_seen,created_at,updated_at,hasfirstnamefilled,haslastnamefilled
1,2018,t,f,f,t,f,male,fr,2018-05-30 12:53:55+00,2018-05-30 12:53:55.57+00,2018-05-30 12:54:11.554+00,t,t
```