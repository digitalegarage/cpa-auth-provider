# Exports

Export sub project provides a container that periodically exports data from IDP database into a CSV file and push it into a specified HDFS.

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
user_id,year_of_birth,haslocalaccount,isfacebookaccountlinked,isgoogleaccountlinked,isemailaddressverfied,gender,language,last_seen,created_at,updated_at,hasfirstnamefilled,haslastnamefilled
1,2018,t,f,f,f,male,fr,2018-05-30 12:53:55+00,2018-05-30 12:53:55.57+00,2018-05-30 12:54:11.554+00,t,t
```

| column | description |
| ------- | ------------- |
| user_id | The user id |
| year_of_birth | the user birth year |
| haslocalaccount | true if user has a local login (i.e.: login using mail/password) |
| isfacebookaccountlinked | true if user has a facebook account linked with his account |
| isgoogleaccountlinked |  true if user has a google account linked with his account | 
| isemailaddressverfied | true if user has local account and email had been verified or if user has no local account |
| gender | gender | 
| language | user language (by default browser local) | 
| last_seen | the last time user has login using local login or social login | 
| created_at | the account creation date |
| updated_at | last time profile was updated |
| hasfirstnamefilled | true if user has a firstname in his profile | 
| haslastnamefilled | true if user has a lastname in his profile |
