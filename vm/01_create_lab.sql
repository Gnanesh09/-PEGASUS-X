-- Run as PostgreSQL administrator inside YOUR isolated Ubuntu lab VM.
-- Creates a small synthetic demo database and a restricted test role.
CREATE DATABASE pegasus_lab;
\c pegasus_lab

CREATE ROLE pegasus_app LOGIN PASSWORD 'CHANGE_THIS_APP_PASSWORD';
CREATE ROLE pegasus_test LOGIN PASSWORD 'CHANGE_THIS_TEST_PASSWORD';

CREATE TABLE public.demo_customers (
  customer_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  display_name TEXT NOT NULL,
  region TEXT NOT NULL
);
INSERT INTO public.demo_customers(display_name, region) VALUES
 ('Customer A','Karnataka'),('Customer B','Tamil Nadu'),('Customer C','Maharashtra');

CREATE TABLE public.restricted_demo (
  record_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  note TEXT NOT NULL
);
INSERT INTO public.restricted_demo(note) VALUES
 ('Synthetic restricted record - no real personal data');

GRANT CONNECT ON DATABASE pegasus_lab TO pegasus_app, pegasus_test;
GRANT USAGE ON SCHEMA public TO pegasus_app, pegas_test;
GRANT SELECT ON public.demo_customers TO pegas_app;
GRANT SELECT ON public.demo_customers TO pegas_test;
-- Deliberately do NOT grant pegasus_test access to restricted_demo.
ALTER ROLE pegasus_app SET statement_timeout = '5s';
ALTER ROLE pegasus_test SET statement_timeout = '2s';
-- Enforce read-only defaults for both Pegasus roles.
ALTER ROLE pegasus_app SET default_transaction_read_only = on;
ALTER ROLE pegasus_test SET default_transaction_read_only = on;
