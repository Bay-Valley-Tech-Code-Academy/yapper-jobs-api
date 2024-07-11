#CREATE DATABASE Yapper_Jobs;

USE Yapper_Jobs;

CREATE TABLE Employer (
	employer_id BINARY(16) PRIMARY KEY,
	first_name VARCHAR(255) NOT NULL,
	last_name VARCHAR(255) NOT NULL,
	user_pass VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	mobile VARCHAR(18) NOT NULL,
	company VARCHAR(255) NOT NULL,
	website TEXT NOT NULL,
	industry VARCHAR(32) NOT NULL,
	approver BOOLEAN NOT NULL DEFAULT 0,
	approve_flag BOOLEAN NOT NULL DEFAULT 0,
	delete_flag BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE Job (
	title VARCHAR(255),
	job_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
	company VARCHAR(255) NOT NULL,
	city VARCHAR(255),
	state VARCHAR(2),
    is_remote BOOLEAN NOT NULL DEFAULT 0,
	industry VARCHAR(255),
	website TEXT,
	experience_level VARCHAR(255),
	employment_type VARCHAR(255) NOT NULL,
	company_size VARCHAR(255),
	salary_low INT3,
	salary_high INT3,
	benefits JSON,
	certifications JSON,
	job_description TEXT NOT NULL,
	questions JSON,
	delete_flag BOOLEAN NOT NULL DEFAULT 0,
	date_created DATETIME,
	expires BOOLEAN,
    date_expires DATETIME,
	employer_id BINARY(16),
	PRIMARY KEY (job_id),
	FOREIGN KEY (employer_id) REFERENCES Employer(employer_id)
);

CREATE TABLE Seeker (
	seeker_id BINARY(16) PRIMARY KEY,
	first_name VARCHAR(255) NOT NULL,
	last_name VARCHAR(255) NOT NULL,
	user_pass VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL,
	education_entries TINYINT NOT NULL DEFAULT 0,
	experience_entries TINYINT NOT NULL DEFAULT 0,
	skill_entries TINYINT NOT NULL DEFAULT 0,
	link_entries TINYINT NOT NULL DEFAULT 0,
	publication_entries TINYINT NOT NULL DEFAULT 0,
	summary TEXT(640),
    resume_uploaded BOOLEAN DEFAULT FALSE,
    resume_url TEXT(2080) DEFAULT NULL,
	delete_flag BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE Education (
	seeker_id BINARY(16) NOT NULL,
	institution_name TINYTEXT NOT NULL,
	education_level TINYTEXT NOT NULL,
	education_field TINYTEXT NOT NULL,
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
	address TINYTEXT,
	city TINYTEXT NOT NULL,
	state TINYTEXT NOT NULL,
	date_start DATE NOT NULL,
	date_end DATE,
	present BOOLEAN NOT NULL,
	job_description TEXT(640),
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
	link_url TEXT(2080) NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Publication (
	seeker_id BINARY(16) NOT NULL,
	publication_name TINYTEXT NOT NULL,
	publication_url TEXT(2080) NOT NULL,
	publication_date DATE NOT NULL,
	publication_summary TEXT(640) NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id)
);

CREATE TABLE Application (
	seeker_id BINARY(16) NOT NULL,
	job_id INT UNSIGNED NOT NULL,
    app_index INT UNSIGNED AUTO_INCREMENT UNIQUE KEY,
	answers JSON,
	date_applied DATETIME DEFAULT CURRENT_TIMESTAMP,
    seen BOOLEAN DEFAULT FALSE,
    accepted BOOLEAN DEFAULT FALSE,
    rejected BOOLEAN DEFAULT FALSE,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id),
	FOREIGN KEY (job_id) REFERENCES Job(job_id)
);

CREATE TABLE Saved_Job (
	seeker_id BINARY(16) NOT NULL,
	job_id INT UNSIGNED NOT NULL,
	FOREIGN KEY (seeker_id) REFERENCES Seeker(seeker_id),
	FOREIGN KEY (job_id) REFERENCES Job(job_id)
);

# initial users needed for proper function
INSERT INTO Seeker(seeker_id, first_name, last_name, user_pass, email)
VALUE(UNHEX('00000000000000000000000000000001'), "example", "example", "elpmaxe", "example@example.com");

INSERT INTO Employer(employer_id, first_name, last_name, user_pass, email, mobile, company, website, industry)
VALUE(UNHEX('00000000000000000000000000000000'), "example", "example", "elpmaxe", "elpmxe@example.com", "12095550123", "example", "example.com", "example");

INSERT INTO Job (title, company, city, state, industry, website, experience_level, employment_type, company_size, salary_low, salary_high, benefits, certifications, job_description, questions, employer_id, job_id)
VALUE('example', 'example', 'example', 'EX', 'example', 'example', 'example', 'example', 0, 0, 0, NULL, NULL, 'bob', NULL, UNHEX('00000000000000000000000000000000'), 12357);

INSERT INTO Application (seeker_id, job_id, answers)
VALUE(UNHEX('00000000000000000000000000000001'), 1, null);

# how to read plaintext uuid:
# SELECT HEX(<column>) FROM <table>;
# undo with UNHEX()
#
#
# how to width numbers:
# SELECT LPAD(<column>, <width>, 0) FROM <table>;
#
# For date comparison
# SELECT EXTRACT(year_month  FROM '2019-07-02 01:02:03');
#
# For date display
# SELECT DATE_FORMAT('2009-10-04 22:23:00', '%Y-%m');
