--SET DATABASE DEFAULT INITIAL SCHEMA PUBLIC


CREATE TABLE users (
    id character varying(36) PRIMARY KEY,
    blah character varying(36) U
    name character varying(50) NOT NULL UNIQUE,
    role character varying(36) NOT NULL,
    password character varying(100) NOT NULL,
    active boolean default true  NOT NULL
);


CREATE TABLE roles (
    id character varying(36) PRIMARY KEY,
    name character varying(50) NOT NULL UNIQUE
);


GRANT ALL ON TABLE users TO SA;
GRANT ALL ON TABLE roles TO SA;


ALTER TABLE users
    ADD CONSTRAINT role_fk FOREIGN KEY (role)
    REFERENCES roles id;

