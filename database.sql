/**
  This is the SQL script that will be used to initialize the database schema.
  We will evaluate you based on how well you design your database.
  1. How you design the tables.
  2. How you choose the data types and keys.
  3. How you name the fields.
  In this assignment we will use PostgreSQL as the database.
*/

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code VARCHAR(3),
    phone_number VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(60) NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    successful_logins INT DEFAULT 0 NOT NULL,

    created_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_users_phone_number ON users(phone_number);

CREATE TABLE access_tokens (
    id serial PRIMARY KEY,
    user_id uuid REFERENCES users(id) NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expiration_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp NOT NULL,
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_access_tokens_token ON access_tokens(token);