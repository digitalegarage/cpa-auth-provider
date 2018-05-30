#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE ROLE `echo $DOCKER_USER` WITH LOGIN PASSWORD '`echo $DOCKER_PASSWORD`';
    CREATE DATABASE idp;
    GRANT ALL PRIVILEGES ON DATABASE idp TO `echo $DOCKER_USER`;

    CREATE SEQUENCE public."Users_id_seq";

    ALTER SEQUENCE public."Users_id_seq"
    OWNER TO dockeridp;

    CREATE TABLE public."Users"
    (
        id integer NOT NULL DEFAULT nextval('"Users_id_seq"'::regclass),
        tracking_uid character varying(255) COLLATE pg_catalog."default",
        enable_sso boolean,
        display_name character varying(255) COLLATE pg_catalog."default",
        photo_url character varying(255) COLLATE pg_catalog."default",
        firstname character varying(255) COLLATE pg_catalog."default",
        lastname character varying(255) COLLATE pg_catalog."default",
        gender character varying(255) COLLATE pg_catalog."default",
        date_of_birth bigint,
        language character varying(255) COLLATE pg_catalog."default",
        last_seen bigint,
        scheduled_for_deletion_at timestamp with time zone,
        created_at timestamp with time zone NOT NULL,
        updated_at timestamp with time zone NOT NULL,
        identity_provider_id integer,
        permission_id integer,
        CONSTRAINT "Users_pkey" PRIMARY KEY (id),
        CONSTRAINT "Users_identity_provider_id_fkey" FOREIGN KEY (identity_provider_id)
            REFERENCES public."IdentityProviders" (id) MATCH SIMPLE
            ON UPDATE CASCADE
            ON DELETE SET NULL,
        CONSTRAINT "Users_permission_id_fkey" FOREIGN KEY (permission_id)
            REFERENCES public."Permissions" (id) MATCH SIMPLE
            ON UPDATE CASCADE
            ON DELETE SET NULL
    )
    WITH (
        OIDS = FALSE
    )
    TABLESPACE pg_default;

    ALTER TABLE public."Users"
        OWNER to dockeridp;


    CREATE SEQUENCE public."SocialLogins_id_seq";

    ALTER SEQUENCE public."SocialLogins_id_seq"
        OWNER TO dockeridp;


    CREATE TABLE public."SocialLogins"
    (
        id integer NOT NULL DEFAULT nextval('"SocialLogins_id_seq"'::regclass),
        name character varying(255) COLLATE pg_catalog."default",
        uid character varying(255) COLLATE pg_catalog."default",
        email character varying(255) COLLATE pg_catalog."default",
        firstname character varying(255) COLLATE pg_catalog."default",
        lastname character varying(255) COLLATE pg_catalog."default",
        gender character varying(255) COLLATE pg_catalog."default",
        date_of_birth bigint,
        language character varying(255) COLLATE pg_catalog."default",
        last_login_at bigint,
        created_at timestamp with time zone NOT NULL,
        updated_at timestamp with time zone NOT NULL,
        user_id integer,
        CONSTRAINT "SocialLogins_pkey" PRIMARY KEY (id),
        CONSTRAINT "SocialLogins_user_id_fkey" FOREIGN KEY (user_id)
            REFERENCES public."Users" (id) MATCH SIMPLE
            ON UPDATE CASCADE
            ON DELETE CASCADE
    )
    WITH (
        OIDS = FALSE
    )
    TABLESPACE pg_default;

    -- DROP INDEX public.social_logins_user_id_name;

    CREATE UNIQUE INDEX social_logins_user_id_name
        ON public."SocialLogins" USING btree
        (user_id, name COLLATE pg_catalog."default")
        TABLESPACE pg_default;

    CREATE SEQUENCE public."LocalLogins_id_seq";

    ALTER SEQUENCE public."LocalLogins_id_seq"
    OWNER TO dockeridp;

    CREATE TABLE public."LocalLogins"
    (
        id integer NOT NULL DEFAULT nextval('"LocalLogins_id_seq"'::regclass),
        login character varying(255) COLLATE pg_catalog."default",
        password character varying(255) COLLATE pg_catalog."default",
        verified boolean,
        password_changed_at bigint,
        last_login_at bigint,
        created_at timestamp with time zone NOT NULL,
        updated_at timestamp with time zone NOT NULL,
        user_id integer,
        CONSTRAINT "LocalLogins_pkey" PRIMARY KEY (id),
        CONSTRAINT "LocalLogins_login_key" UNIQUE (login),
        CONSTRAINT "LocalLogins_user_id_fkey" FOREIGN KEY (user_id)
            REFERENCES public."Users" (id) MATCH SIMPLE
            ON UPDATE CASCADE
            ON DELETE SET NULL
    )
    WITH (
        OIDS = FALSE
    )
    TABLESPACE pg_default;

    ALTER TABLE public."LocalLogins"
        OWNER to dockeridp;
EOSQL