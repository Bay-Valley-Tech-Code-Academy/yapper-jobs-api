CREATE DATABASE Yapper_Jobs;

USE Yapper_Jobs;

CREATE TABLE Employer (
	employer_id BINARY(16) PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    user_pass VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	mobile VARCHAR(18) NOT NULL,
	company VARCHAR(255) NOT NULL,
	website VARCHAR(255) NOT NULL,
	industry VARCHAR(32) NOT NULL,
    approver BOOLEAN NOT NULL DEFAULT 0,
    approve_flag BOOLEAN NOT NULL DEFAULT 0,
    delete_flag BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE Job (
	job_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    location VARCHAR(255) NOT NULL,
    industry VARCHAR(255) NOT NULL,
    experience_level VARCHAR(255) NOT NULL,
    employment_type VARCHAR(255) NOT NULL,
    company_size VARCHAR(255) NOT NULL,
    salary_low INT NOT NULL,
    salary_high INT NOT NULL,
    benefits INT NOT NULL,
    certifications INT NOT NULL,
    job_description TEXT NOT NULL,
    questions JSON,
    delete_flag BOOLEAN NOT NULL DEFAULT 0,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    employer_id BINARY(16),
    PRIMARY KEY (job_id),
    FOREIGN KEY (employer_id) REFERENCES Employer(employer_id)
);

CREATE TABLE Seeker (
	seeker_id BINARY(16) PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    user_pass VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
	education_entries TINYINT NOT NULL DEFAULT 0,
	experience_entries TINYINT NOT NULL DEFAULT 0,
	skill_entries TINYINT NOT NULL DEFAULT 0,
	link_entries TINYINT NOT NULL DEFAULT 0,
	publication_entries TINYINT NOT NULL DEFAULT 0,
	summary TEXT(640),
    delete_flag BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE Education (
	seeker_id BINARY(16) NOT NULL,
	institution_name VARCHAR(255) NOT NULL,
	education_level VARCHAR(255) NOT NULL,
	education_field VARCHAR(255) NOT NULL,
	date_start DATE NOT NULL,
	date_end DATE,
	present BOOLEAN NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Experience (
	seeker_id BINARY(16) NOT NULL,
	job_title TINYTEXT NOT NULL,
	company_name TINYTEXT NOT NULL,
	remote BOOLEAN NOT NULL,
	address_street TINYTEXT,
	address_city TINYTEXT NOT NULL,
	address_country TINYTEXT NOT NULL,
	date_start DATE NOT NULL,
	date_end DATE,
	present BOOLEAN NOT NULL,
	description TEXT(640),
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Skill (
	seeker_id BINARY(16) NOT NULL,
	skill_name TINYTEXT NOT NULL,
	skill_years TINYINT NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Url (
	seeker_id BINARY(16) NOT NULL,
	link_name TINYTEXT NOT NULL,
	link_url text(2080) NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Publication (
	seeker_id BINARY(16) NOT NULL,
	publication_name TINYTEXT NOT NULL,
	publication_url VARCHAR(2080) NOT NULL,
	publication_date DATE NOT NULL,
	publication_summary TEXT(640) NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Application (
	seeker_id BINARY(16) NOT NULL,
	job_id INT UNSIGNED NOT NULL,
	answers JSON,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id),
	FOREIGN KEY (job_id) REFERENCES Job(job_id)
);

# initial users needed for proper function
insert into Seeker(seeker_id, user_name, user_pass, email)
value(uuid_to_bin(uuid()), "example", "example", "example@example.com");

insert into Employer(employer_id, user_name, user_pass, email, mobile, company, website, industry)
value(uuid_to_bin(uuid()), "example", "example", "example@example.com", "12095550123", "example", "example.com", "example");


# how to read plaintext uuid:
# SELECT hex(seeker_id) FROM Seeker;
#
#
#
#
