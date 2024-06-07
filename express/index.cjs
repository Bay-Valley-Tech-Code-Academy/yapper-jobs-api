const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const fs = require("fs");
const { rateLimit } = require("express-rate-limit");
const { fetchAndSaveJobs } = require("./jobDataHandler");
const {
  checkUser,
  checkAuth,
  login,
  setTimestamp,
  validSAN,
  validA,
  validN,
  validState,
  validJSON,
} = require("./helper.js");
const { title } = require("process");
require("dotenv").config();

// Call fetchAndSaveJobs function to fetch and save job data
//Comment this code block out to avoid fetching data from the API each time you run server
// try {
//   fetchAndSaveJobs();
//   console.log("Fetch API Successful")
// } catch (error) {
//   console.error("Error fetching and saving jobs:", error);
// }

const corsOptions = {
  origin: "http://localhost:5173",
  credentials: true,
  optionSuccessStatus: 200,
};

const time = new Date(Date.now()); // used to log server start
const writer = fs.createWriteStream("./ape.log", { flags: "a" }); // open log for appending, creates file if it does not exist

const app = express();
const port = process.env.PORT; // default port

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res, next) => {
    const newTime = new Date(Date.now()); // for logging
    writer.write(
      `${setTimestamp(
        newTime
      )} | status: 429 | source: /login | error: Too Many Requests | ${
        req.body.email
      }@${req.socket.remoteAddress}\n`
    );
    res.status(429).json({ success: false, error: "Too Many Requests" });
  },
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res, next) => {
    const newTime = new Date(Date.now()); // for logging
    writer.write(
      `${setTimestamp(
        newTime
      )} | status: 429 | source: /register | error: Too Many Requests | ${
        req.body.email
      }@${req.socket.remoteAddress}\n`
    );
    res.status(429).json({ success: false, error: "Too Many Requests" });
  },
});

app.use(cors(corsOptions));

app.use(bodyParser.json());

// Setup connection to MySQL server
app.use(async (req, res, next) => {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);
    await next();
    req.db.release();
  } catch (err) {
    console.log(err);
    if (req.db) req.db.release();
    throw err;
  }
});

app.use("/login", loginLimiter);
app.use("/register", registerLimiter);

// Register endpoint for job seeker
app.post("/register/seeker", async (req, res) => {
  console.log("registration attempt: seeker");
  const timeNow = Math.ceil(Date.now() / 1000); // for jwt expiration
  const newTime = new Date(Date.now()); // for logging
  writer.write(`${setTimestamp(newTime)} | Registration attempt: seeker\n`);
  const { firstName, lastName, pass, email } = req.body;
  try {
    // check if input exists and is safe
    if (!firstName || !lastName || !pass || !email) {
      throw {
        status: 400,
        error: "failed seeker add",
        reason: "missing field",
      };
    }
    if (
      !validA(firstName) ||
      !validA(lastName) ||
      !validSAN(pass) ||
      !validSAN(email)
    ) {
      throw {
        status: 400,
        error: "failed seeker add",
        reason: "invalid input",
      };
    }
    // check if user or email already exists
    let check;
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw { status: 500, error: err, reason: "check failed" };
    }
    if (check.exists !== false) {
      throw { status: 400, error: "failed seeker add", reason: check.reason };
    }
    // encrypt password, add user to database, respond to caller, and log successful registration
    await bcrypt.hash(pass, 10).then(async (hash) => {
      try {
        const [user] = await req.db.query(
          `
          INSERT INTO Seeker (seeker_id, first_name, last_name, user_pass, email)
          VALUES (uuid_to_bin(uuid()), :first_name, :last_name, :pass, :email);
        `,
          {
            first_name: firstName,
            last_name: lastName,
            pass: hash,
            email: email,
          }
        );
        const users = await login(req, email, pass, "seeker");

        res.status(200).json({
          success: true,
          // id: users.user_id,
          firstName: users.first_name,
          lastName: users.last_name,
          email: users.email,
          jwt: users.jwt,
        });
        writer.write(
          `${setTimestamp(
            newTime
          )} | status: 201 | source: /register/seeker | success: job seeker added | ${email}@${
            req.socket.remoteAddress
          }\n`
        );
      } catch (err) {
        res.status(500).json({ success: false, error: "server failure" });
        console.warn(err);
        writer.write(
          `${setTimestamp(
            newTime
          )} | status: 500 | source: /register/seeker bcrypt\.then | error: ${err} | attempt: ${email}@${
            req.socket.remoteAddress
          }\n`
        );
      }
    });
  } catch (err) {
    console.warn(err);
    if (!err.reason) {
      res.status(500).json({ success: false, error: "server failure" });
      writer.write(
        `${setTimestamp(
          newTime
        )} | status: 500 | source: /register/seeker | error: ${err} | @${
          req.socket.remoteAddress
        }\n`
      );
    } else {
      res
        .status(!err.status ? 500 : err.status)
        .json({ success: false, error: err.reason });
      writer.write(
        `${setTimestamp(newTime)} | status: ${
          !err.status ? 500 : err.status
        } | source: /register/seeker | error: ${err.error} | reason: ${
          err.reason
        } | @${req.socket.remoteAddress}\n`
      );
    }
  }
});

// Register endpoint for employer
app.post("/register/employer", async (req, res) => {
  console.log("Registration attempt: employer");
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | registration attempt: employer\n`);
  const {
    firstName,
    lastName,
    pass,
    email,
    mobile,
    company,
    website,
    industry,
  } = req.body;
  try {
    let check;
    if (
      !firstName ||
      !lastName ||
      !pass ||
      !email ||
      !mobile ||
      !company ||
      !website ||
      !industry
    ) {
      throw {
        status: 400,
        error: "failed employer add",
        reason: "missing field",
      };
    }
    if (
      !validA(firstName) ||
      !validA(lastName) ||
      !validSAN(pass) ||
      !validSAN(email) ||
      !validSAN(mobile) ||
      !validSAN(company) ||
      !validSAN(website) ||
      !validA(industry)
    ) {
      throw {
        status: 400,
        error: "failed employer add",
        reason: "invalid input",
      };
    }
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw { status: 500, error: err, reason: "check failed" };
    }
    if (check.exists !== false) {
      throw { status: 400, error: "failed employer add", reason: check.reason };
    }
    await bcrypt.hash(pass, 10).then(async (hash) => {
      try {
        const [user] = await req.db.query(
          `
          INSERT INTO Employer (employer_id, first_name, last_name, user_pass, email, mobile, company, website, industry)
          VALUES (uuid_to_bin(uuid()), :first_name, :last_name, :pass, :email, :mobile, :company, :website, industry);
        `,
          {
            first_name: firstName,
            last_name: lastName,
            pass: hash,
            email: email,
            mobile: mobile,
            company: company,
            website: website,
            industry: industry,
          }
        );
        const users = await login(req, email, pass, "employer");
        console.log(user);
        res.status(200).json({
          success: true,
          firstName: users.firstName,
          lastName: users.lastName,
          email: users.email,
          company: users.company,
          jwt: users.jwt,
        });
        writer.write(
          `${setTimestamp(
            newTime
          )} | status: 201 | source: /register/employer | success: employer ${email} @ ${company} added | @${
            req.socket.remoteAddress
          }\n`
        );
      } catch (err) {
        res.status(500).json({ success: false, error: "server failure" });
        console.warn(err);
        writer.write(
          `${setTimestamp(
            newTime
          )} | status: 500 | source: /register/employer bcrypt\.then | error: ${err} | attempt: ${email}@${
            req.socket.remoteAddress
          }\n`
        );
      }
    });
  } catch (err) {
    console.warn(err);
    if (!err.reason) {
      res.status(500).json({ success: false, error: "server failure" });
      writer.write(
        `${setTimestamp(
          newTime
        )} | status: 500 | source: /register/employer | error: ${err} | attempt: ${email}@${
          req.socket.remoteAddress
        }\n`
      );
    } else {
      res
        .status(!err.status ? 500 : err.status)
        .json({ success: false, error: err.reason });
      writer.write(
        `${setTimestamp(newTime)} | status: ${
          !err.status ? 500 : err.status
        } | source: /register/employer | error: ${err.error} | reason: ${
          err.reason
        } | attempt: ${email}@${req.socket.remoteAddress}\n`
      );
    }
  }
});

// Login endpoint for job seeker
app.post("/login/seeker", async (req, res) => {
  console.log("login attempt: seeker");
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | login attempt: seeker\n`);
  const { email, pass } = req.body;
  try {
    let check;
    if (!email || !pass) {
      throw {
        status: 400,
        error: "failed seeker login",
        reason: "missing field",
      };
    }
    if (!validSAN(email) || !validSAN(pass)) {
      throw {
        status: 400,
        error: "failed seeker login",
        reason: "invalid input",
      };
    }
    check = await checkUser(req, email);
    if (check.exists === false) {
      throw {
        status: 400,
        error: "failed seeker login",
        reason: "user not found",
      };
    }
    const users = await login(req, email, pass, "seeker");
    res.status(200).json({
      success: true,
      jwt: users.jwt,
      // user: {
      //   // id: users.id ? users.id : "No id found",
      //   firstName: users.firstName,
      //   lastName: users.lastName,
      //   email: users.email,
      //   jwt: users.jwt,
      // },
    });
    writer.write(
      `${setTimestamp(
        newTime
      )} | status: 200 | source: /login/seeker | login: seeker ${email} logged in | @${
        req.socket.remoteAddress
      }\n`
    );
  } catch (err) {
    console.warn(err);
    if (!err.reason) {
      res.status(500).json({ success: false, error: "server failure" });
      writer.write(
        `${setTimestamp(
          newTime
        )} | status: 500 | source: /login/seeker | error: ${err} | attempt: ${email}@${
          req.socket.remoteAddress
        }\n`
      );
    } else {
      res
        .status(!err.status ? 500 : err.status)
        .json({ success: false, error: err.reason });
      writer.write(
        `${setTimestamp(newTime)} | status: ${
          !err.status ? 500 : err.status
        } | source: /login/seeker | error: ${err.error} | reason: ${
          err.reason
        } | attempt: ${email}@${req.socket.remoteAddress}\n`
      );
    }
  }
});

// Login endpoint for employer
app.post("/login/employer", async (req, res) => {
  console.log("login attempt: employer");
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | login attempt: employer\n`);
  const { email, pass } = req.body;
  try {
    let check;
    if (!email || !pass) {
      throw {
        status: 400,
        error: "failed employer login",
        reason: "missing field",
      };
    }
    if (!validSAN(email) || !validSAN(pass)) {
      throw {
        status: 400,
        error: "failed employer login",
        reason: "invalid input",
      };
    }
    check = await checkUser(req, email);
    if (check.exists == false) {
      throw {
        status: 400,
        error: "failed employer login",
        reason: "user not found",
      };
    }
    const users = await login(req, email, pass, "employer");

    res.status(200).json({
      success: true,
      firstName: users.firstName,
      lastName: users.lastName,
      email: users.email,
      company: users.company,
      jwt: users.jwt,
    });
    writer.write(
      `${setTimestamp(
        newTime
      )} | status: 200 | source: /login/employer | success: ${users.email} @ ${
        users.company
      } logged in | @${req.socket.remoteAddress}\n`
    );
  } catch (err) {
    console.warn(err);
    if (!err.reason) {
      res.status(500).json({ success: false, error: "server failure" });
      writer.write(
        `${setTimestamp(
          newTime
        )} | status: 500 | source: /login/employer | error: ${err} | attempt: ${email}@${
          req.socket.remoteAddress
        }\n`
      );
    } else {
      res
        .status(!err.status ? 500 : err.status)
        .json({ success: false, error: err.reason });
      writer.write(
        `${setTimestamp(newTime)} | status: ${
          !err.status ? 500 : err.status
        } | source: /login/employer | error: ${err.error} | reason: ${
          err.reason
        } | attempt: ${email}@${req.socket.remoteAddress}\n`
      );
    }
  }
});

//fetch jobs table from database
app.get("/api/jobs", async (req, res) => {
  try {
    const [jobs] = await req.db.query("SELECT * FROM job");
    res.status(200).json({ success: true, data: jobs });
  } catch (err) {
    console.error("Error fetching jobs:", err);
    res.status(500).json({ success: false, error: "Failed to fetch jobs" });
  }
});

// JWT verification checks to see if there is an authorization header with a valid JWT in it.
app.use(async function verifyJwt(req, res, next) {
  console.log("Verify attempt: JWT");
  const newTime = new Date(Date.now()); // for logging
  writer.write(
    `${setTimestamp(newTime)} | verify attempt: JWT | attempt: @${
      req.socket.remoteAddress
    }\n`
  );
  try {
    if (!req.headers.authorization) {
      throw {
        status: 400,
        error: "failed JWT verify",
        reason: "invalid authorization, no authorization headers",
      };
      // writer.write(`${setTimestamp(newTime)} | Verify attempt: JWT\n`);
      // res.status(400).json({error: 'Invalid authorization, no authorization headers'});
    }

    const [scheme, token] = req.headers.authorization.split(" ");

    if (scheme !== "Bearer" || token === null) {
      throw {
        status: 400,
        error: "failed JWT verify",
        reason: "invalid authorization, invalid authorization scheme",
      };
      // res.status(400).json({error: 'Invalid authorization, invalid authorization scheme'});
    }

    try {
      const payload = jwt.verify(token, process.env.JWT_KEY);
      req.user = payload;
      writer.write(
        `${setTimestamp(newTime)} | Verify attempt: JWT | attempt: ${
          req.user.email
        }@${req.socket.remoteAddress}\n`
      );
    } catch (err) {
      console.log(err);
      if (
        err.message &&
        (err.message.toUpperCase() === "INVALID TOKEN" ||
          err.message.toUpperCase() === "JWT EXPIRED" ||
          err.message.toUpperCase() === "JWT MALFORMED")
      ) {
        req.status = err.status || 500;
        req.body = err.message;
        req.app.emit("jwt-error", err, req);
        throw { status: 400, error: "failed JWT verify", reason: err.message };
      } else {
        throw (err.status || 500, err.message);
      }
    }
  } catch (err) {
    console.warn(err);
    if (!err.reason) {
      res.status(500).json({ success: false, error: "server failure" });
      writer.write(
        `${setTimestamp(
          newTime
        )} | status: 500 | source: JWT | error: ${err} | @${
          req.socket.remoteAddress
        }\n`
      );
    } else {
      res
        .status(!err.status ? 500 : err.status)
        .json({ success: false, error: err.reason });
      writer.write(
        `${setTimestamp(newTime)} | status: ${
          !err.status ? 500 : err.status
        } | source: JWT | error: ${err.error} | reason: ${err.reason} | @${
          req.socket.remoteAddress
        }\n`
      );
    }
  }

  await next();
});

/*  job_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    company VARCHAR(255) NOT NULL,
    city VARCHAR(255) NOT NULL,
    state VARCHAR(2) NOT NULL,
    zip int3 NOT NULL,
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
    employer_id BINARY(16), */
// Add new job endpoint
app.post("/add-job", async (req, res) => {
  console.log("Add attempt: job");
  const newTime = new Date(Date.now()); // for logging
  writer.write(`${setTimestamp(newTime)} | add attempt: job\n`);
  // api body MUST send null object for empty json inputs
  const {
    title,
    city,
    state,
    zip,
    experienceLevel,
    employmentType,
    companySize,
    salaryLow,
    salaryHigh,
    benefits,
    certifications,
    jobDescription,
    questions,
  } = req.body;
  try {
    // check if input exists and is safe
    if (
      !title ||
      !city ||
      !state ||
      !zip ||
      !experienceLevel ||
      !employmentType ||
      !companySize ||
      !salaryLow ||
      !salaryHigh ||
      !jobDescription
    ) {
      throw { status: 400, error: "failed job add", reason: "missing field" };
    }
    if (
      !validSAN(title) ||
      !validA(city) ||
      !validState(state) ||
      !validN(zip) ||
      !validA(experienceLevel) ||
      !validSAN(employmentType) ||
      !validN(companySize) ||
      !validN(salaryLow) ||
      !validN(salaryHigh) ||
      !validJSON(benefits) ||
      !validJSON(certifications) ||
      !validSAN(jobDescription) ||
      !validJSON(questions)
    ) {
      throw { status: 400, error: "failed job add", reason: "invalid input" };
    }
    // check if user authorized to post jobs for the company
    let check;
    try {
      check = await checkAuth(req, req.user.user_id, req.user.company);
    } catch (err) {
      throw { status: 500, error: err, reason: "authorization failed" };
    }
    if (check === false) {
      throw { status: 500, error: "failed job add", reason: "failed approval" };
    }
    try {
      const [[employer]] = await req.db.query(
        `
        SELECT industry, website FROM Employer WHERE employer_id = UNHEX(:user_id);
      `,
        {
          user_id: req.user.user_id,
        }
      );
      const job = await req.db.query(
        `
        INSERT INTO Job (title, company, city, state, zip, industry, website, experience_level, employment_type, company_size, salary_low, salary_high, benefits, certifications, job_description, questions, employer_id)
        VALUES (:title, :company, :city, :state, :zip, :industry, :website, :experience_level, :employment_type, :company_size, :salary_low, :salary_high, :benefits, :certifications, :job_description, :questions, UNHEX(:employer_id));
      `,
        {
          title: title,
          company: req.user.company,
          city: city,
          state: state,
          zip: zip,
          industry: employer.industry,
          website: employer.website,
          experience_level: experienceLevel,
          employment_type: employmentType,
          company_size: companySize,
          salary_low: salaryLow,
          salary_high: salaryHigh,
          benefits: benefits,
          certifications: certifications,
          job_description: jobDescription,
          questions: questions,
          employer_id: req.user.user_id,
        }
      );
      const [[jobId]] = await req.db.query(
        `
        SELECT job_id FROM Job 
        WHERE employer_id = UNHEX(:user_id)
        ORDER BY created DESC
        LIMIT 1;
      `,
        {
          user_id: req.user.user_id,
        }
      );
      res.status(200).json({
        success: true,
        jobId: jobId.job_id,
      });
      writer.write(
        `${setTimestamp(newTime)} | status: 201 | source: /add-job | success: ${
          req.user.email
        } @ ${req.user.company} added job id: ${jobId.job_id} | @${
          req.socket.remoteAddress
        }\n`
      );
    } catch (err) {
      throw { status: 500, error: "failed job add", reason: err.message };
    }
  } catch (err) {
    console.warn(err);
    if (!err.reason) {
      res.status(500).json({ success: false, error: "server failure" });
      writer.write(
        `${setTimestamp(
          newTime
        )} | status: 500 | source: /login/employer | error: ${
          err.message
        } | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`
      );
    } else {
      res
        .status(!err.status ? 500 : err.status)
        .json({ success: false, error: err.reason });
      writer.write(
        `${setTimestamp(newTime)} | status: ${
          !err.status ? 500 : err.status
        } | source: /login/employer | error: ${err.error} | reason: ${
          err.reason
        } | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`
      );
    }
  }
});

// from here

//fetch user from seeker table
app.get("/seeker", async (req, res) => {
  const seeker_id = req.user.user_id;
  const email = req.user.email;

  if (!seeker_id) {
    return res.status(400).json({ error: "Missing seeker_id" });
  }

  try {
    let check;
    check = await checkUser(req, email);
    if (check.exists == false) {
      throw {
        status: 400,
        error: "failed to get seeker",
        reason: "user not found",
      };
    }
    const [rows] = await req.db.query(
      `SELECT first_name, last_name FROM seeker WHERE seeker_id = UNHEX(:seeker_id)`,
      {
        seeker_id: seeker_id,
      }
    );
    res.status(200).json(rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to get seeker" });
  }
});


//save job to database
app.post("/save-job", async (req, res) => {
  const seeker_id = req.user.user_id;
  const email = req.user.email;
  const { job_id } = req.body;

  if (!seeker_id || !job_id) {
    return res.status(400).json({ error: "Missing seeker_id or job_id" });
  }

  try {
    let check;
    check = await checkUser(req, email);
    if (check.exists == false) {
      throw {
        status: 400,
        error: "failed to save job",
        reason: "user not found",
      };
    }
    await req.db.query(
      "INSERT INTO saved_job (seeker_id, job_id) VALUE (UNHEX(:seeker_id), :job_id)",
      {
        seeker_id: seeker_id,
        job_id: job_id,
      }
    );
    res.status(200).json({ message: "Job saved successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to save job" });
  }
});

//fetch saved jobs from database
app.get("/saved-jobs", async (req, res) => {
  const seeker_id = req.user.user_id;
  const email = req.user.email;

  if (!req.user.user_id) {
    return res.status(400).json({ error: "Missing seeker_id" });
  }

  try {
    let check;
    check = await checkUser(req, email);
    if (check.exists == false) {
      throw {
        status: 400,
        error: "failed to get saved jobs",
        reason: "user not found",
      };
    }
    const [rows] = await req.db.query(
      `SELECT job.* 
       FROM saved_job 
       INNER JOIN job ON saved_job.job_id = job.job_id 
       WHERE saved_job.seeker_id = UNHEX(:seeker_id)`,
      {
        seeker_id: seeker_id,
      }
    );
    res.status(200).json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to get saved jobs" });
  }
});

//remove job
app.delete("/saved-jobs/:jobId", async (req, res) => {
  const seeker_id = req.user.user_id;
  const jobId = req.params.jobId;

  if (!seeker_id || !jobId) {
    return res.status(400).json({ error: "Missing seeker_id or jobId" });
  }

  try {
    const [result] = await req.db.query(
      `DELETE FROM saved_job WHERE seeker_id = UNHEX(:seeker_id) AND job_id = :jobId`,
      {
        seeker_id: seeker_id,
        jobId: jobId,
      }
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Job not found" });
    }

    res.status(200).json({ message: "Job removed successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to remove job" });
  }
});

const bob = "re";

//add a logout endpoint
app.post("/logout", (req, res) => {
  const newTime = new Date(Date.now()); // for logging
  writer.write(`${setTimestamp(newTime)} | logout attempt\n`);
  
  // Clear client-side data instructions.
  res.status(200).json({ success: true, message: "Logout successful. Please clear your token from the client." });
  writer.write(
      `${setTimestamp(newTime)} | status: 200 | source: /logout | success: user logged out | @${
          req.socket.remoteAddress
      }\n`
  );
});


app.listen(port, () => {
  console.log(
    `server started on http://${process.env.DB_HOST}:${port} @ ${time}`
  );
  console.log("test log");
  writer.write(`${setTimestamp(time)} | port: ${port} | server started\n`);
});
