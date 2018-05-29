#!/usr/bin/env bash
#PGPASSWORD=SchiefesHausBautFalsch
export PGPASSWORD="SchiefesHausBautFalsch"
psql -h 192.168.1.181 -p 5432 -U dockeridp idp -c "\COPY (SELECT U.id as user_id, date_part('year', TO_TIMESTAMP(U.date_of_birth/1000)) as year_of_birth, LL.id IS NOT NULL as hasLocalAccount, FB.id IS NOT NULL as isFacebookAccountLinked, GOOGLE.id IS NOT NULL as isGoogleAccountLinked,  LL.id IS NOT NULL as hasLocalAccount, LL.verified IS NOT NULL as isEmailAddressVerfied, U.gender, U.language, TO_TIMESTAMP(U.last_seen/1000) as last_seen, U.created_at, U.updated_at, U.firstname IS NOT NULL as hasFirstNameFilled, U.lastname IS NOT NULL as hasLastNameFilled  FROM public.\"Users\" U  LEFT JOIN public.\"LocalLogins\" LL ON U.id = LL.user_id LEFT JOIN public.\"SocialLogins\" GOOGLE ON U.id = GOOGLE.user_id AND GOOGLE.name = 'google' LEFT JOIN public.\"SocialLogins\" FB ON U.id = FB.user_id AND FB.name = 'facebook') TO './export.csv' DELIMITER ',' CSV HEADER"

