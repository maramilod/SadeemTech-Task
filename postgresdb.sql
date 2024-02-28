CREATE DATABASE fiber_demo;
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    image VARCHAR(255),
    email VARCHAR(255),
    password VARCHAR(255),
    role VARCHAR(255)
);
INSERT INTO users (name, email, password, role, image) VALUES ('Admin', 'Admin@gmail.com', '123', 'admin', 'a.png');
