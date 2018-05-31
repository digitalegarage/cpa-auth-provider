--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.5
-- Dumped by pg_dump version 10.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: enum_Clients_registration_type; Type: TYPE; Schema: public; Owner: dockeridp
--

CREATE TYPE public."enum_Clients_registration_type" AS ENUM (
    'dynamic',
    'static'
);


ALTER TYPE public."enum_Clients_registration_type" OWNER TO dockeridp;

--
-- Name: enum_PairingCodes_state; Type: TYPE; Schema: public; Owner: dockeridp
--

CREATE TYPE public."enum_PairingCodes_state" AS ENUM (
    'pending',
    'verified',
    'denied'
);


ALTER TYPE public."enum_PairingCodes_state" OWNER TO dockeridp;

--
-- Name: enum_ValidationCodes_type; Type: TYPE; Schema: public; Owner: dockeridp
--

CREATE TYPE public."enum_ValidationCodes_type" AS ENUM (
    'email',
    'account'
);


ALTER TYPE public."enum_ValidationCodes_type" OWNER TO dockeridp;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: AccessTokens; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."AccessTokens" (
    id integer NOT NULL,
    token character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    client_id integer,
    domain_id integer,
    user_id integer
);


ALTER TABLE public."AccessTokens" OWNER TO dockeridp;

--
-- Name: AccessTokens_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."AccessTokens_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."AccessTokens_id_seq" OWNER TO dockeridp;

--
-- Name: AccessTokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."AccessTokens_id_seq" OWNED BY public."AccessTokens".id;


--
-- Name: Clients; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."Clients" (
    id integer NOT NULL,
    secret character varying(255),
    name character varying(255),
    software_id character varying(255),
    software_version character varying(255),
    ip character varying(255),
    registration_type public."enum_Clients_registration_type" DEFAULT 'dynamic'::public."enum_Clients_registration_type",
    redirect_uri character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer
);


ALTER TABLE public."Clients" OWNER TO dockeridp;

--
-- Name: Clients_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."Clients_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."Clients_id_seq" OWNER TO dockeridp;

--
-- Name: Clients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."Clients_id_seq" OWNED BY public."Clients".id;


--
-- Name: Domains; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."Domains" (
    id integer NOT NULL,
    name character varying(255),
    display_name character varying(255),
    access_token character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public."Domains" OWNER TO dockeridp;

--
-- Name: Domains_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."Domains_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."Domains_id_seq" OWNER TO dockeridp;

--
-- Name: Domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."Domains_id_seq" OWNED BY public."Domains".id;


--
-- Name: IdentityProviders; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."IdentityProviders" (
    id integer NOT NULL,
    name character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public."IdentityProviders" OWNER TO dockeridp;

--
-- Name: IdentityProviders_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."IdentityProviders_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."IdentityProviders_id_seq" OWNER TO dockeridp;

--
-- Name: IdentityProviders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."IdentityProviders_id_seq" OWNED BY public."IdentityProviders".id;


--
-- Name: LocalLogins; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."LocalLogins" (
    id integer NOT NULL,
    login character varying(255),
    password character varying(255),
    verified boolean,
    password_changed_at bigint,
    last_login_at bigint,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer
);


ALTER TABLE public."LocalLogins" OWNER TO dockeridp;

--
-- Name: LocalLogins_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."LocalLogins_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."LocalLogins_id_seq" OWNER TO dockeridp;

--
-- Name: LocalLogins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."LocalLogins_id_seq" OWNED BY public."LocalLogins".id;


--
-- Name: OAuth2AuthorizationCodes; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."OAuth2AuthorizationCodes" (
    id integer NOT NULL,
    authorization_code character varying(255),
    redirect_uri character varying(255),
    state character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    oauth2_client_id integer,
    user_id integer,
    o_auth2_client_id integer
);


ALTER TABLE public."OAuth2AuthorizationCodes" OWNER TO dockeridp;

--
-- Name: OAuth2AuthorizationCodes_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."OAuth2AuthorizationCodes_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."OAuth2AuthorizationCodes_id_seq" OWNER TO dockeridp;

--
-- Name: OAuth2AuthorizationCodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."OAuth2AuthorizationCodes_id_seq" OWNED BY public."OAuth2AuthorizationCodes".id;


--
-- Name: OAuth2Clients; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."OAuth2Clients" (
    id integer NOT NULL,
    client_id character varying(255),
    client_secret character varying(255),
    jwt_code character varying(255),
    name character varying(255),
    redirect_uri character varying(255),
    use_template character varying(255),
    email_redirect_uri character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer
);


ALTER TABLE public."OAuth2Clients" OWNER TO dockeridp;

--
-- Name: OAuth2Clients_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."OAuth2Clients_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."OAuth2Clients_id_seq" OWNER TO dockeridp;

--
-- Name: OAuth2Clients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."OAuth2Clients_id_seq" OWNED BY public."OAuth2Clients".id;


--
-- Name: OAuth2RefreshTokens; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."OAuth2RefreshTokens" (
    id integer NOT NULL,
    key character varying(255),
    expires_at bigint,
    scope character varying(255),
    consumed boolean,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer,
    oauth2_client_id integer
);


ALTER TABLE public."OAuth2RefreshTokens" OWNER TO dockeridp;

--
-- Name: OAuth2RefreshTokens_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."OAuth2RefreshTokens_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."OAuth2RefreshTokens_id_seq" OWNER TO dockeridp;

--
-- Name: OAuth2RefreshTokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."OAuth2RefreshTokens_id_seq" OWNED BY public."OAuth2RefreshTokens".id;


--
-- Name: PairingCodes; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."PairingCodes" (
    id integer NOT NULL,
    device_code character varying(255),
    user_code character varying(255),
    verification_uri character varying(255),
    state public."enum_PairingCodes_state" DEFAULT 'pending'::public."enum_PairingCodes_state",
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    client_id integer,
    domain_id integer,
    user_id integer
);


ALTER TABLE public."PairingCodes" OWNER TO dockeridp;

--
-- Name: PairingCodes_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."PairingCodes_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."PairingCodes_id_seq" OWNER TO dockeridp;

--
-- Name: PairingCodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."PairingCodes_id_seq" OWNED BY public."PairingCodes".id;


--
-- Name: Permissions; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."Permissions" (
    id integer NOT NULL,
    label character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public."Permissions" OWNER TO dockeridp;

--
-- Name: Permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."Permissions_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."Permissions_id_seq" OWNER TO dockeridp;

--
-- Name: Permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."Permissions_id_seq" OWNED BY public."Permissions".id;


--
-- Name: SequelizeMeta; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."SequelizeMeta" (
    name character varying(255) NOT NULL
);


ALTER TABLE public."SequelizeMeta" OWNER TO dockeridp;

--
-- Name: Sessions; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."Sessions" (
    sid character varying(32) NOT NULL,
    expires timestamp with time zone,
    data text,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


ALTER TABLE public."Sessions" OWNER TO dockeridp;

--
-- Name: SocialLogins; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."SocialLogins" (
    id integer NOT NULL,
    name character varying(255),
    uid character varying(255),
    email character varying(255),
    firstname character varying(255),
    lastname character varying(255),
    gender character varying(255),
    date_of_birth bigint,
    language character varying(255),
    last_login_at bigint,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer
);


ALTER TABLE public."SocialLogins" OWNER TO dockeridp;

--
-- Name: SocialLogins_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."SocialLogins_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."SocialLogins_id_seq" OWNER TO dockeridp;

--
-- Name: SocialLogins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."SocialLogins_id_seq" OWNED BY public."SocialLogins".id;


--
-- Name: UserEmailTokens; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."UserEmailTokens" (
    key character varying(255) NOT NULL,
    type character varying(255),
    sub character varying(255),
    redirect_uri character varying(255),
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer,
    oauth2_client_id integer
);


ALTER TABLE public."UserEmailTokens" OWNER TO dockeridp;

--
-- Name: Users; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."Users" (
    id integer NOT NULL,
    tracking_uid character varying(255),
    enable_sso boolean,
    display_name character varying(255),
    photo_url character varying(255),
    firstname character varying(255),
    lastname character varying(255),
    gender character varying(255),
    date_of_birth bigint,
    language character varying(255),
    last_seen bigint,
    scheduled_for_deletion_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    identity_provider_id integer,
    permission_id integer
);


ALTER TABLE public."Users" OWNER TO dockeridp;

--
-- Name: Users_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."Users_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."Users_id_seq" OWNER TO dockeridp;

--
-- Name: Users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."Users_id_seq" OWNED BY public."Users".id;


--
-- Name: ValidationCodes; Type: TABLE; Schema: public; Owner: dockeridp
--

CREATE TABLE public."ValidationCodes" (
    id integer NOT NULL,
    date bigint,
    value character varying(255),
    type public."enum_ValidationCodes_type" DEFAULT 'email'::public."enum_ValidationCodes_type",
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    user_id integer
);


ALTER TABLE public."ValidationCodes" OWNER TO dockeridp;

--
-- Name: ValidationCodes_id_seq; Type: SEQUENCE; Schema: public; Owner: dockeridp
--

CREATE SEQUENCE public."ValidationCodes_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public."ValidationCodes_id_seq" OWNER TO dockeridp;

--
-- Name: ValidationCodes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: dockeridp
--

ALTER SEQUENCE public."ValidationCodes_id_seq" OWNED BY public."ValidationCodes".id;


--
-- Name: AccessTokens id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."AccessTokens" ALTER COLUMN id SET DEFAULT nextval('public."AccessTokens_id_seq"'::regclass);


--
-- Name: Clients id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Clients" ALTER COLUMN id SET DEFAULT nextval('public."Clients_id_seq"'::regclass);


--
-- Name: Domains id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Domains" ALTER COLUMN id SET DEFAULT nextval('public."Domains_id_seq"'::regclass);


--
-- Name: IdentityProviders id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."IdentityProviders" ALTER COLUMN id SET DEFAULT nextval('public."IdentityProviders_id_seq"'::regclass);


--
-- Name: LocalLogins id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."LocalLogins" ALTER COLUMN id SET DEFAULT nextval('public."LocalLogins_id_seq"'::regclass);


--
-- Name: OAuth2AuthorizationCodes id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2AuthorizationCodes" ALTER COLUMN id SET DEFAULT nextval('public."OAuth2AuthorizationCodes_id_seq"'::regclass);


--
-- Name: OAuth2Clients id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2Clients" ALTER COLUMN id SET DEFAULT nextval('public."OAuth2Clients_id_seq"'::regclass);


--
-- Name: OAuth2RefreshTokens id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2RefreshTokens" ALTER COLUMN id SET DEFAULT nextval('public."OAuth2RefreshTokens_id_seq"'::regclass);


--
-- Name: PairingCodes id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."PairingCodes" ALTER COLUMN id SET DEFAULT nextval('public."PairingCodes_id_seq"'::regclass);


--
-- Name: Permissions id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Permissions" ALTER COLUMN id SET DEFAULT nextval('public."Permissions_id_seq"'::regclass);


--
-- Name: SocialLogins id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."SocialLogins" ALTER COLUMN id SET DEFAULT nextval('public."SocialLogins_id_seq"'::regclass);


--
-- Name: Users id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Users" ALTER COLUMN id SET DEFAULT nextval('public."Users_id_seq"'::regclass);


--
-- Name: ValidationCodes id; Type: DEFAULT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."ValidationCodes" ALTER COLUMN id SET DEFAULT nextval('public."ValidationCodes_id_seq"'::regclass);


--
-- Data for Name: AccessTokens; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."AccessTokens" (id, token, created_at, updated_at, client_id, domain_id, user_id) FROM stdin;
\.


--
-- Data for Name: Clients; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."Clients" (id, secret, name, software_id, software_version, ip, registration_type, redirect_uri, created_at, updated_at, user_id) FROM stdin;
\.


--
-- Data for Name: Domains; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."Domains" (id, name, display_name, access_token, created_at, updated_at) FROM stdin;
1	sp:8002	Example Service Provider	b4949eba147f4cf88985b43c039cd05b	2018-05-30 12:50:39.875+00	2018-05-30 12:50:39.875+00
\.


--
-- Data for Name: IdentityProviders; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."IdentityProviders" (id, name, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: LocalLogins; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."LocalLogins" (id, login, password, verified, password_changed_at, last_login_at, created_at, updated_at, user_id) FROM stdin;
1	dominique.chion@gmail.com	{BC}$2a$10$kZ0I.x1kIaGPgtcDH4yUxeSdE4P9xv0vft754Q8UbRhH8CZn1Okt6	\N	1527684835651	1527684835676	2018-05-30 12:53:55.575+00	2018-05-30 12:53:55.676+00	1
\.


--
-- Data for Name: OAuth2AuthorizationCodes; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."OAuth2AuthorizationCodes" (id, authorization_code, redirect_uri, state, created_at, updated_at, oauth2_client_id, user_id, o_auth2_client_id) FROM stdin;
\.


--
-- Data for Name: OAuth2Clients; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."OAuth2Clients" (id, client_id, client_secret, jwt_code, name, redirect_uri, use_template, email_redirect_uri, created_at, updated_at, user_id) FROM stdin;
\.


--
-- Data for Name: OAuth2RefreshTokens; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."OAuth2RefreshTokens" (id, key, expires_at, scope, consumed, created_at, updated_at, user_id, oauth2_client_id) FROM stdin;
\.


--
-- Data for Name: PairingCodes; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."PairingCodes" (id, device_code, user_code, verification_uri, state, created_at, updated_at, client_id, domain_id, user_id) FROM stdin;
\.


--
-- Data for Name: Permissions; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."Permissions" (id, label, created_at, updated_at) FROM stdin;
1	admin	2018-05-30 12:50:39.874+00	2018-05-30 12:50:39.874+00
2	other	2018-05-30 12:50:39.874+00	2018-05-30 12:50:39.874+00
\.


--
-- Data for Name: SequelizeMeta; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."SequelizeMeta" (name) FROM stdin;
10001-domains.js
10002-identity-providers.js
10003-users.js
10004-clients.js
10005-access-tokens.js
10006-oauth2-clients.js
10007-oauth2-authorization-codes.js
10008-pairing-codes.js
10009-user-profiles.js
20001-user-email-tokens.js
20170801093844-email-verified.js
20170801093845-permissions.js
20170801093845b-permissions-table.js
20170801093846-oauth2-client-secret.js
20170801093848-users-multi-changes.js
20170801093849-oauth2-refresh-tokens.js
20170801093850-user-profiles-language.js
20170801093851-validation-codes.js
20170810085118-deletion-scheduled.js
20170922074954-profile-date-of-birth.js
20170929115500-extract-external-provider.js
20180115120000-change-email-in-social-account-1-schema.js
20180115120002-change-email-in-social-account-2-data.js
20180115120003-change-email-in-social-account-3-schema.js
20180115120004-change-email-in-social-account-4-sequences.js
20180213095428-login-constraints.js
20180222150000-oauth_custom_template.js
20180511100000-login-case-insensitive.js
\.


--
-- Data for Name: Sessions; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."Sessions" (sid, expires, data, "createdAt", "updatedAt") FROM stdin;
HDX1SbF4OJzs9GvDNrJQOH-Ajxvc1lpb	2019-05-30 12:53:41.146+00	{"cookie":{"originalMaxAge":31536000000,"expires":"2019-05-30T12:53:41.146Z","secure":false,"httpOnly":true,"path":"/"},"auth_origin":"/"}	2018-05-30 12:53:41.183+00	2018-05-30 12:53:41.183+00
UQw5jg9Sd_qjFjRP4jT4INi0RKrjBgD6	2019-05-30 12:54:11.612+00	{"cookie":{"originalMaxAge":31536000000,"expires":"2019-05-30T12:54:11.612Z","secure":false,"httpOnly":true,"path":"/"},"flash":{},"passport":{"user":1}}	2018-05-30 12:53:41.221+00	2018-05-30 12:54:11.615+00
\.


--
-- Data for Name: SocialLogins; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."SocialLogins" (id, name, uid, email, firstname, lastname, gender, date_of_birth, language, last_login_at, created_at, updated_at, user_id) FROM stdin;
\.


--
-- Data for Name: UserEmailTokens; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."UserEmailTokens" (key, type, sub, redirect_uri, created_at, updated_at, user_id, oauth2_client_id) FROM stdin;
\.


--
-- Data for Name: Users; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."Users" (id, tracking_uid, enable_sso, display_name, photo_url, firstname, lastname, gender, date_of_birth, language, last_seen, scheduled_for_deletion_at, created_at, updated_at, identity_provider_id, permission_id) FROM stdin;
1	\N	\N	Dominique Chion	\N	Dominique	Chion	male	1522792800000	fr	1527684835704	\N	2018-05-30 12:53:55.57+00	2018-05-30 12:54:11.554+00	\N	\N
\.


--
-- Data for Name: ValidationCodes; Type: TABLE DATA; Schema: public; Owner: dockeridp
--

COPY public."ValidationCodes" (id, date, value, type, created_at, updated_at, user_id) FROM stdin;
1	1527684835666	237b6a5bd6c76a3e1e00471c210e99	email	2018-05-30 12:53:55.666+00	2018-05-30 12:53:55.666+00	1
\.


--
-- Name: AccessTokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."AccessTokens_id_seq"', 1, false);


--
-- Name: Clients_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."Clients_id_seq"', 1, false);


--
-- Name: Domains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."Domains_id_seq"', 1, true);


--
-- Name: IdentityProviders_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."IdentityProviders_id_seq"', 1, false);


--
-- Name: LocalLogins_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."LocalLogins_id_seq"', 1, true);


--
-- Name: OAuth2AuthorizationCodes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."OAuth2AuthorizationCodes_id_seq"', 1, false);


--
-- Name: OAuth2Clients_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."OAuth2Clients_id_seq"', 1, false);


--
-- Name: OAuth2RefreshTokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."OAuth2RefreshTokens_id_seq"', 1, false);


--
-- Name: PairingCodes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."PairingCodes_id_seq"', 1, false);


--
-- Name: Permissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."Permissions_id_seq"', 1, false);


--
-- Name: SocialLogins_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."SocialLogins_id_seq"', 1, false);


--
-- Name: Users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."Users_id_seq"', 1, true);


--
-- Name: ValidationCodes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: dockeridp
--

SELECT pg_catalog.setval('public."ValidationCodes_id_seq"', 1, true);


--
-- Name: AccessTokens AccessTokens_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."AccessTokens"
    ADD CONSTRAINT "AccessTokens_pkey" PRIMARY KEY (id);


--
-- Name: Clients Clients_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Clients"
    ADD CONSTRAINT "Clients_pkey" PRIMARY KEY (id);


--
-- Name: Domains Domains_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Domains"
    ADD CONSTRAINT "Domains_pkey" PRIMARY KEY (id);


--
-- Name: IdentityProviders IdentityProviders_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."IdentityProviders"
    ADD CONSTRAINT "IdentityProviders_pkey" PRIMARY KEY (id);


--
-- Name: LocalLogins LocalLogins_login_key; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."LocalLogins"
    ADD CONSTRAINT "LocalLogins_login_key" UNIQUE (login);


--
-- Name: LocalLogins LocalLogins_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."LocalLogins"
    ADD CONSTRAINT "LocalLogins_pkey" PRIMARY KEY (id);


--
-- Name: OAuth2AuthorizationCodes OAuth2AuthorizationCodes_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2AuthorizationCodes"
    ADD CONSTRAINT "OAuth2AuthorizationCodes_pkey" PRIMARY KEY (id);


--
-- Name: OAuth2Clients OAuth2Clients_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2Clients"
    ADD CONSTRAINT "OAuth2Clients_pkey" PRIMARY KEY (id);


--
-- Name: OAuth2RefreshTokens OAuth2RefreshTokens_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2RefreshTokens"
    ADD CONSTRAINT "OAuth2RefreshTokens_pkey" PRIMARY KEY (id);


--
-- Name: PairingCodes PairingCodes_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."PairingCodes"
    ADD CONSTRAINT "PairingCodes_pkey" PRIMARY KEY (id);


--
-- Name: Permissions Permissions_label_key; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Permissions"
    ADD CONSTRAINT "Permissions_label_key" UNIQUE (label);


--
-- Name: Permissions Permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Permissions"
    ADD CONSTRAINT "Permissions_pkey" PRIMARY KEY (id);


--
-- Name: SequelizeMeta SequelizeMeta_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."SequelizeMeta"
    ADD CONSTRAINT "SequelizeMeta_pkey" PRIMARY KEY (name);


--
-- Name: Sessions Sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Sessions"
    ADD CONSTRAINT "Sessions_pkey" PRIMARY KEY (sid);


--
-- Name: SocialLogins SocialLogins_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."SocialLogins"
    ADD CONSTRAINT "SocialLogins_pkey" PRIMARY KEY (id);


--
-- Name: UserEmailTokens UserEmailTokens_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."UserEmailTokens"
    ADD CONSTRAINT "UserEmailTokens_pkey" PRIMARY KEY (key);


--
-- Name: Users Users_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Users"
    ADD CONSTRAINT "Users_pkey" PRIMARY KEY (id);


--
-- Name: ValidationCodes ValidationCodes_pkey; Type: CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."ValidationCodes"
    ADD CONSTRAINT "ValidationCodes_pkey" PRIMARY KEY (id);


--
-- Name: o_auth2_refresh_tokens_key; Type: INDEX; Schema: public; Owner: dockeridp
--

CREATE UNIQUE INDEX o_auth2_refresh_tokens_key ON public."OAuth2RefreshTokens" USING btree (key);


--
-- Name: social_logins_user_id_name; Type: INDEX; Schema: public; Owner: dockeridp
--

CREATE UNIQUE INDEX social_logins_user_id_name ON public."SocialLogins" USING btree (user_id, name);


--
-- Name: AccessTokens AccessTokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."AccessTokens"
    ADD CONSTRAINT "AccessTokens_client_id_fkey" FOREIGN KEY (client_id) REFERENCES public."Clients"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: AccessTokens AccessTokens_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."AccessTokens"
    ADD CONSTRAINT "AccessTokens_domain_id_fkey" FOREIGN KEY (domain_id) REFERENCES public."Domains"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: AccessTokens AccessTokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."AccessTokens"
    ADD CONSTRAINT "AccessTokens_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: Clients Clients_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Clients"
    ADD CONSTRAINT "Clients_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: LocalLogins LocalLogins_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."LocalLogins"
    ADD CONSTRAINT "LocalLogins_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: OAuth2AuthorizationCodes OAuth2AuthorizationCodes_o_auth2_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2AuthorizationCodes"
    ADD CONSTRAINT "OAuth2AuthorizationCodes_o_auth2_client_id_fkey" FOREIGN KEY (o_auth2_client_id) REFERENCES public."OAuth2Clients"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: OAuth2AuthorizationCodes OAuth2AuthorizationCodes_oauth2_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2AuthorizationCodes"
    ADD CONSTRAINT "OAuth2AuthorizationCodes_oauth2_client_id_fkey" FOREIGN KEY (oauth2_client_id) REFERENCES public."OAuth2Clients"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: OAuth2AuthorizationCodes OAuth2AuthorizationCodes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2AuthorizationCodes"
    ADD CONSTRAINT "OAuth2AuthorizationCodes_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: OAuth2Clients OAuth2Clients_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2Clients"
    ADD CONSTRAINT "OAuth2Clients_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: OAuth2RefreshTokens OAuth2RefreshTokens_oauth2_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2RefreshTokens"
    ADD CONSTRAINT "OAuth2RefreshTokens_oauth2_client_id_fkey" FOREIGN KEY (oauth2_client_id) REFERENCES public."OAuth2Clients"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: OAuth2RefreshTokens OAuth2RefreshTokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."OAuth2RefreshTokens"
    ADD CONSTRAINT "OAuth2RefreshTokens_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: PairingCodes PairingCodes_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."PairingCodes"
    ADD CONSTRAINT "PairingCodes_client_id_fkey" FOREIGN KEY (client_id) REFERENCES public."Clients"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: PairingCodes PairingCodes_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."PairingCodes"
    ADD CONSTRAINT "PairingCodes_domain_id_fkey" FOREIGN KEY (domain_id) REFERENCES public."Domains"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: PairingCodes PairingCodes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."PairingCodes"
    ADD CONSTRAINT "PairingCodes_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: SocialLogins SocialLogins_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."SocialLogins"
    ADD CONSTRAINT "SocialLogins_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: UserEmailTokens UserEmailTokens_oauth2_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."UserEmailTokens"
    ADD CONSTRAINT "UserEmailTokens_oauth2_client_id_fkey" FOREIGN KEY (oauth2_client_id) REFERENCES public."OAuth2Clients"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: UserEmailTokens UserEmailTokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."UserEmailTokens"
    ADD CONSTRAINT "UserEmailTokens_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: Users Users_identity_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Users"
    ADD CONSTRAINT "Users_identity_provider_id_fkey" FOREIGN KEY (identity_provider_id) REFERENCES public."IdentityProviders"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: Users Users_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."Users"
    ADD CONSTRAINT "Users_permission_id_fkey" FOREIGN KEY (permission_id) REFERENCES public."Permissions"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: ValidationCodes ValidationCodes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: dockeridp
--

ALTER TABLE ONLY public."ValidationCodes"
    ADD CONSTRAINT "ValidationCodes_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public."Users"(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

