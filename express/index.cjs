const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
const { rateLimit } = require('express-rate-limit');
const {checkUser, checkAuth, login, setTimestamp, validSAN, validSA, validA, validN, validState, validJSON, validExpDate, validDate, validDates} = require('./helper.js');
const { title } = require('process');
const { error } = require('console');
const { sendEmail, sendApplication, sendDelete } = require('./Email.js');
require('dotenv').config();

const corsOptions = {
  origin: 'http://localhost:5173', 
  credentials: true,
  optionSuccessStatus: 200,
}

let it = 0;

// for testing
function bob(msg) {
  if(msg === undefined) {
    console.log(it);
    it++;
  } else if (msg === 'reset') {
    console.log('resetting count');
    it = 0;
  } else {
    console.log(msg);
  }
}

const time = new Date(Date.now());// used to log server start
const writer = fs.createWriteStream('./ape.log', {flags: 'a'});// open log for appending, creates file if it does not exist

const app = express();
const port = process.env.PORT; // default port

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res, next) => {
    const newTime = new Date(Date.now());// for logging
    writer.write(`${setTimestamp(newTime)} | status: 429 | source: /login | error: Too Many Requests | | ${req.body.email}@${req.socket.remoteAddress}\n`);
    res.status(429).json({success: false, error: 'Too Many Requests'});
  }
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res, next) => {
    const newTime = new Date(Date.now());// for logging
    writer.write(`${setTimestamp(newTime)} | status: 429 | source: /register | error: Too Many Requests | | ${req.body.email}@${req.socket.remoteAddress}\n`);
    res.status(429).json({success: false, error: 'Too Many Requests'});
  }
});

const resumeLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 2,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res, next) => {
    const newTime = new Date(Date.now());// for logging
    writer.write(`${setTimestamp(newTime)} | status: 429 | source: /resume | error: Too Many Requests | | ${req.body.email}@${req.socket.remoteAddress}\n`);
    res.status(429).json({success: false, error: 'Too Many Requests'});
  }
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

app.use('/login', loginLimiter);
app.use('/register', registerLimiter);
//app.use('/resume', resumeLimiter);

// Register endpoint for job seeker
app.post('/register/seeker', async (req, res) => {
  console.log('registration attempt: seeker');
  const timeNow = Math.ceil(Date.now() / 1000);// for jwt expiration
  const newTime = new Date(Date.now());// for logging
  const {
    firstName,
    lastName,
    pass,
    email
  } = req.body;
  writer.write(`${setTimestamp(newTime)} | | source: /register/seeker | info: Registration attempt: seeker | | attempt: ${email}@${req.socket.remoteAddress}\n`);
  try {
    // check if input exists and is safe
    if(!firstName || !lastName || !pass || !email) {
      throw({status: 400, error: 'failed seeker add', reason: 'missing field'});
    }
    if(!validSA(firstName, 255) || !validSA(lastName, 255) || !validSAN(pass, 255) || !validSAN(email, 255)) {
      throw({status: 400, error: 'failed seeker add', reason: 'invalid input'});
    }
    // check if user or email already exists
    let check;
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists !== false) {
      throw({status: 400, error: 'failed seeker add', reason: check.reason});
    }
    // encrypt password, add user to database, respond to caller, and log successful registration
    await bcrypt.hash(pass, 10)
    .then(async hash => {
      try {
        const [user] = await req.db.query(`
          INSERT INTO Seeker (seeker_id, first_name, last_name, user_pass, email)
          VALUES (uuid_to_bin(uuid()), :first_name, :last_name, :pass, :email);
        `, {
          first_name: firstName,
          last_name: lastName,
          pass: hash,
          email: email
        });
        const users = await login(req, email, pass, 'seeker');
        
        res.status(200)
        .json({
          success: true, 
          firstName: users.firstName,
          lastName: users.lastName,
          email: users.email,
          jwt: users.jwt
        });
        writer.write(`${setTimestamp(newTime)} | status: 201 | source: /register/seeker | success: job seeker added | | ${email}@${req.socket.remoteAddress}\n`);
      } catch (err) {
        res.status(500).json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/seeker bcrypt\.then | error: ${err.message} | | attempt: ${email}@${req.socket.remoteAddress}\n`);
      }});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/seeker | error: ${err.message} | | @${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /register/seeker | error: ${err.error} | reason: ${err.reason} | @${req.socket.remoteAddress}\n`);
    }
  }
});

// Register endpoint for employer
app.post('/register/employer', async (req, res) => {
  console.log('Registration attempt: employer');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  const {
    firstName,
    lastName,
    pass,
    email,
    mobile,
    company,
    website,
    industry
  } = req.body;
  writer.write(`${setTimestamp(newTime)} | | source: /register/employer | info: registration attempt: employer | | attempt: ${email}@${req.socket.remoteAddress}\n`);
  try {
    if(
      !firstName ||
      !lastName ||
      !pass ||
      !email ||
      !mobile ||
      !company ||
      !website ||
      !industry
    ) {
      throw({status: 400, error: 'failed employer add', reason: 'missing field'});
    }
    if(
      !validSA(firstName, 255)  ||
      !validSA(lastName, 255)   ||
      !validSAN(pass, 255)      ||
      !validSAN(email, 255)     ||
      !validSAN(mobile, 15)     ||
      !validSAN(company, 255)   ||
      !validSAN(website, 2047)  ||
      !validA(industry, 255)
    ) {
      throw({status: 400, error: 'failed employer add', reason: 'invalid input'});
    }
    let check;
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists !== false) {
      throw({status: 400, error: 'failed employer add', reason: check.reason});
    }
    await bcrypt.hash(pass, 10)
    .then(async (hash) => {
      try {
        const [user] = await req.db.query(`
          INSERT INTO Employer (employer_id, first_name, last_name, user_pass, email, mobile, company, website, industry)
          VALUES (uuid_to_bin(uuid()), :first_name, :last_name, :pass, :email, :mobile, :company, :website, industry);
        `, {
          first_name: firstName,
          last_name: lastName,
          pass: hash,
          email: email,
          mobile: mobile,
          company: company,
          website: website,
          industry: industry
        });
        const users = await login(req, email, pass, 'employer');
        console.log(user)
        res.status(200)
        .json({
          success: true,
          firstName: users.firstName,
          lastName: users.lastName,
          email: users.email,
          company: users.company,
          jwt: users.jwt
        });
        writer.write(`${setTimestamp(newTime)} | status: 201 | source: /register/employer | success: employer ${email} @ ${company} added | | @${req.socket.remoteAddress}\n`);
      } catch (err) {
        res.status(500).json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/employer bcrypt\.then | error: ${err.message} | | attempt: ${email}@${req.socket.remoteAddress}\n`);
      }});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/employer | error: ${err.message} | | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /register/employer | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// Login endpoint for job seeker
app.post('/login/seeker', async (req, res) => {
  console.log('login attempt: seeker');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  const {email, pass} = req.body;
  writer.write(`${setTimestamp(newTime)} | | source: /login/seeker | info: login attempt: seeker | | attempt: ${email}@${req.socket.remoteAddress}\n`);
  try {
    if(!email || !pass) {
      throw({status: 400, error: 'failed seeker login', reason: 'missing field'});
    }
    if(!validSAN(email, 255) || !validSAN(pass, 255)) {
      throw({status: 400, error: 'failed seeker login', reason: 'invalid input'});
    }
    let check;
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed seeker login', reason: 'user not found'});
    }
    const users = await login(req, email, pass, 'seeker');
    if(users.status) {
      throw({status: users.status, error: users.error, reason: users.reason})
    }
    res.status(200)
    .json({
    success: true, 
    firstName: users.firstName,
    lastName: users.lastName,
    email: users.email,
    jwt: users.jwt
    });
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /login/seeker | info: login: seeker ${email} logged in | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /login/seeker | error: ${err.message} | | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /login/seeker | error: ${err.error} | | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// Login endpoint for employer
app.post('/login/employer', async (req, res) => {
  console.log('login attempt: employer');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  const {email, pass} = req.body;
  writer.write(`${setTimestamp(newTime)} | | source: /login/employer | info: login attempt: employer | | attempt: ${email}@${req.socket.remoteAddress}\n`);
  try {
    if(!email || !pass) {
      throw({status: 400, error: 'failed employer login', reason: 'missing field'});
    }
    if(!validSAN(email, 255) || !validSAN(pass, 255)) {
      throw({status: 400, error: 'failed employer login', reason: 'invalid input'});
    }
    let check;
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed employer login', reason: 'user not found'});
    }
    const users = await login(req, email, pass, 'employer');
    if(users.status) {
      throw({status: users.status, error: users.error, reason: users.reason});
    }
    res.status(200).json({
      success: true,
      firstName: users.firstName,
      lastName: users.lastName,
      email: users.email,
      company: users.company,
      jwt: users.jwt});
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /login/employer | success: ${users.email} @ ${users.company} logged in | | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /login/employer | error: ${err.message} | | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /login/employer | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// job search
app.get('/job/search/get', async (req, res) => {
  console.log('get attempt: jobs');
  const newTime = new Date(Date.now());
  //const search_type = req.query.type;
  const keywords = !req.query.key ? null : req.query.key;
  const location = !req.query.loc ? null : req.query.loc;
  const remote = req.query.rem !== 'true' ? false : true;
  const industry = !req.query.ind ? null : req.query.ind;
  const experience_level = !req.query.exp ? null : req.query.exp;
  const employment_type = !req.query.emp ? null : req.query.emp;
  const company_size = !req.query.size ? null : req.query.size;
  const salary_range = !req.query.sal ? null : req.query.sal;
  const benefits = !req.query.ben ? null : req.query.ben;
  const certifications = !req.query.cert ? null : req.query.cert;
  writer.write(`${setTimestamp(newTime)} | | source: /job/search/get | info: get attempt: jobs | | attempt: @${req.socket.remoteAddress}\n`);
  try {
    const start_index = parseInt(req.query.startIndex);
    const per_page = parseInt(req.query.perPage);
    const args = {start_index: start_index, per_page: per_page};
    let search_query = 'SELECT job_id, company, city, state, is_remote, salary_low, salary_high, employment_type FROM Job WHERE (job_id >= :start_index';
    if(remote === true) {
      search_query += ' AND remote = 1';
    } else if(location !== null) {
      if(!validSAN(location)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid location'});
      }
      search_query += ' AND city = :city AND state = :state';
      const loc = location.split('-');// separate city and state
      args.city = loc[0];
      args.state = loc[1];
    }
    if(industry !== null) {
      if(!validSAN(industry)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid industry'});
      }
      search_query += ' AND industry = :industry';
      args.industry = industry;
    }
    if(experience_level !== null) {
      if(!validSAN(experience_level)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid experience level'});
      }
      search_query += ' AND experience_level = :experience_level';
      args.experience_level = experience_level;
    }
    if(employment_type !== null) {
      if(!validSAN(employment_type)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid employment type'});
      }
      search_query += ' AND employment_type = :employment_type';
      args.employment_type = employment_type;
    }
    if(company_size !== null) {
      if(!validSAN(company_size)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid company size'});
      }
      search_query += ' AND company_size = :company_size';
      args.company_size = company_size;
    }
    if(salary_range !== null) {
      let low = 1;
      let high = 999999;
      if(salary_range.indexOf('-') !== -1) {
        const sal = salary_range.split('-');// separate lowest and highest salary desired
        if(sal[0] !== '') {
          args.low = parseInt(sal[0]);
          search_query += ' AND salary_low >= :low';
        }
        args.high = parseInt(sal[1]);
        search_query += ' AND salary_high <= :high';
      } else {
        low = parseInt(salary_range);
        search_query += ' AND salary_low >= :low';
      }
      if(!validN(low) || !validN(high)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'salary out of range'});
      }
    }
    if(benefits !== null) {
      if(!validSAN(benefits)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid benefits'});
      }
      if(benefits.indexOf('-') !== -1) {
        const ben = benefits.split('-');
        for(let i = 0; i < ben.length; i++) {
          search_query += ` AND locate(:ben${i}, JSON_EXTRACT(job.benefits, "$[*]")) > 0`;
          args['ben' + i] = ben[i];
        }
      } else {
        search_query += ' AND locate(:benefits, JSON_EXTRACT(job.benefits, "$[*]")) > 0';
        args.benefits = benefits;
      }
    }
    if(certifications !== null) {
      if(!validSAN(certifications)) {
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'invalid certifications'});
      }
      if(certifications.indexOf('-') !== -1) {
        const cert = certifications.split('-');
        for(let i = 0; i < cert.length; i++) {
          search_query += ` AND locate(:cert${i}, JSON_EXTRACT(job.certifications, "$[*]")) > 0`;
          args['cert' + i] = cert[i];
        }
      } else {
        search_query += ' AND locate(:certifications, JSON_EXTRACT(job.certifications, "$[*]")) > 0';
        args.certifications = certifications;
      }
    }
    if(keywords !== null) {
      let querystr = '';
      if(keywords.indexOf(';') !== -1 || keywords.indexOf('/') !== -1 || keywords.indexOf('\\') !== -1) {
        bob()
        throw({status: 400, error: 'failed get attempt: jobs', reason: 'malformed query'});
      }
      if(keywords.indexOf('"') !== -1) {
        let substr = [];
        const substrquote = keywords.split('"');
        bob(substrquote)
        for(let i = 0; i < substrquote.length; i++) {
          if(!validSAN(substrquote[i]) && substrquote[i]) {
            throw({status: 400, error: 'failed get attempt: jobs', reason: 'malformed query'});
          }
          if(substrquote[i] === '') continue;
          if(i % 2 === 0) {
            bob(i)
            if(substrquote[i].indexOf(' ') !== -1) {
              substr = substr.concat(substrquote[i].split(' '));
            }
          } else {
            const temp = '+"' + substrquote[i] + '"';
            substr.push(temp);
          }
        }
        for(let i = 0; i < substr.length; i++) {
          if(substr[i].length === 0) continue;
          if(!(i + 1 >= substr.length)) {
            substr[i] += ' ';
          }
          querystr += substr[i]
        }
      } else {
        if(!validSAN(keywords) && keywords === undefined) {
          throw({status: 400, error: 'failed get attempt: jobs', reason: 'malformed query'});
        }
        querystr = keywords;
      }
      search_query += ' AND MATCH (title, job_description, company, industry, experience_level, employment_type) AGAINST (:keyword IN BOOLEAN MODE)';
      args.keywords = querystr;
    }
    search_query += ') LIMIT :per_page;';
    bob(search_query)
    bob(args)
    const [jobs] = await req.db.query(search_query, args);
    res.status(200).json({success: true, jobs: jobs});
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /job/search/get | success: search successful | | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/search/get | error: ${err.message} | | attempt: @${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/search/get | error: ${err.error} | reason: ${err.reason} | attempt: @${req.socket.remoteAddress}\n`);
    }
  }
});

// get job details
app.get('/job/:job_id/get', async (req, res) => {
  const job_id = parseInt(req.params.job_id);
  console.log('get attempt: job');
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | | source: /job/${job_id}/get | info: get attempt: job | | attempt: @${req.socket.remoteAddress}\n`);
  try{
    const [[{exist}]] = await req.db.query(`
      SELECT CASE
        WHEN EXISTS(
          SELECT 1
          FROM Job
          WHERE (job_id = :job_id))
        THEN(
          SELECT delete_flag
          FROM Job
          WHERE job_id = :job_id)
        ELSE NULL
      END AS exist;
    `,{
      job_id: job_id,
    });
    switch(exist) {
      case 0:
        break;
      case 1:
      case null:
        throw({status: 404, error: 'failed job get', reason: 'job not found'});
      default:
        throw({status: 500, error: 'failed job get', reason: 'search defaulted'});
    }
    const [[job]] = await req.db.query(`
      SELECT title, company, city, state, ,, industry, website, experience_level, employment_type, company_size, salary_low, salary_high, benefits, certifications, job_description, questions, date_created, expires, date_expires
      FROM Job,
      WHERE job_id = :job_id;
    `,{
      job_id: job_id,
    });
    res.status(200).json({success: true, job: job});
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /job/${job_id}/get | success: got job ${job_id} | | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/${job_id}/get | error: ${err.message} | | attempt: @${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/${job_id}/get | error: ${err.error} | reason: ${err.reason} | attempt: @${req.socket.remoteAddress}\n`);
    }
  }
})

//fetch jobs table from database
app.get("/api/jobs", async (req, res) => {
  try {
    const [jobs] = await req.db.query("SELECT * FROM job");
    res.status(200).json({ success: true, data: jobs });
  } catch (err) {
    console.error('Error fetching jobs:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch jobs' });
  }
});

// forget password, should send email to link
app.post('/forgot-password', async (req, res) => {
  const newTime = new Date(Date.now());
  const { email } = req.body;

  writer.write(`${setTimestamp(newTime)} || source: /forget-password | info: reset attempt: password || attempt: ${email}@${req.socket.remoteAddress}\n`);
  
  try {
    if (!email) {
      throw({status: 400, success: false, error: 'failed reset attempt: password', reason: 'missing field'});
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw({status: 400, success: false, error: 'failed reset attempt: password', reason: 'invalid email format'});
    }

     // Use checkUser helper function
     const user = await checkUser(req, email);

     if (!user.exists) {
      throw({status: 404, success: false, error: 'failed reset attempt: password', reason: 'email not found'});
     }

    const { usertype, userId } = user;

    // Create a reset token
    const resetToken = jwt.sign({email: email, id: userId, type: usertype}, process.env.JWT_KEY, { expiresIn: '1h' });
    const resetLink = `http://localhost:5173/reset-password?token=${resetToken}`;

    await sendEmail(email, 'Password Reset', `Click here to reset your password: ${resetLink}`);

    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /forgot-password | success: Email sent | | ${email}@${req.socket.remoteAddress}\n`);

    res.status(200).json({ success: true, message: 'Reset link sent to email', token: resetToken });
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({ success: false, error: 'Server failure' });
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /forget-password | error: ${err} | | attempt: ${email}@${req.socket.remoteAddress}\n`);
    } 
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /forget-password | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }   
  }
});

// reset password
app.put('/reset-password', async (req, res) => {
  console.log('reset password attempt')
  const newTime = new Date(Date.now());
  const { token, newPassword } = req.body;
  let userId, usertype, email;
  writer.write(`${setTimestamp(newTime)} || source: /reset-password | info: resetting password | | attempt: ${email}@${req.socket.remoteAddress}\n`);

  try {
    if (!token || !newPassword) {
      throw({status: 400, success: false, error: 'failed reset attempt: password', reason: 'missing token or new password'});
    }

    const user = jwt.verify(token, process.env.JWT_KEY);
    userId = user.id;
    usertype = user.type;
    email = user.email;

    const hash = await bcrypt.hash(newPassword, 10);

    let query, params;

    if (usertype === 'seeker') {
      query = 'UPDATE Seeker SET user_pass = :hash WHERE seeker_id = UNHEX(:userId) AND delete_flag = 0;';
      params = { hash, userId };
    } else {
      query = 'UPDATE Employer SET user_pass = :hash WHERE employer_id = UNHEX(:userId) AND delete_flag = 0;';
      params = { hash, userId };
    }

    const result = await req.db.query(query, params);

    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /reset-password | success: Password successfully reset || ${email}@${req.socket.remoteAddress}\n`);

    res.status(200).json({ success: true, message: 'Password reset successful' });
  } catch (err) {
    console.warn(err);

    if(!err.reason) {
      res.status(500).json({ success: false, error: 'Server failure' });
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /reset-password | error: ${err} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    } 
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /reset-password | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    } 
  }
});

// JWT verification checks to see if there is an authorization header with a valid JWT in it.
app.use(async function verifyJwt(req, res, next) {
  console.log('Verify attempt: JWT');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: JWT | info: verify attempt: JWT | | attempt: @${req.socket.remoteAddress}\n`);
  try {
    if (!req.headers.authorization) {
      throw({status: 400, error: 'failed JWT verify', reason: 'invalid authorization, no authorization headers'});
      // writer.write(`${setTimestamp(newTime)} | Verify attempt: JWT\n`);
      // res.status(400).json({error: 'Invalid authorization, no authorization headers'});
    }
  
    const [scheme, token] = req.headers.authorization.split(' ');
    if (scheme !== 'Bearer' || token === null) {
      throw({status: 400, error: 'failed JWT verify', reason: 'invalid authorization, invalid authorization scheme'});
      // res.status(400).json({error: 'Invalid authorization, invalid authorization scheme'});
    }
  
    try {
      bob(1)
      const payload = jwt.verify(token, process.env.JWT_KEY);
      req.user = payload;
      writer.write(`${setTimestamp(newTime)} | | source: JWT | info: verified: JWT | | ${req.user.email}@${req.socket.remoteAddress}\n`)
      bob(2)
      await next();
    } catch (err) {
      console.log(err);
      if (
        err.message && 
        (err.message.toUpperCase() === 'INVALID TOKEN' || 
        err.message.toUpperCase() === 'JWT EXPIRED' ||
        err.message.toUpperCase() ==='JWT MALFORMED')
      ) {
        req.status = err.status || 500;
        req.body = err.message;
        req.app.emit('jwt-error', err, req);
        throw({status: 400, error: 'failed JWT verify', reason: err.message});
      } else {
  
        throw((err.status || 500), err.message);
      }
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: JWT | error: ${err.message} | | @${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: JWT | error: ${err.error} | reason: ${err.reason} | @${req.socket.remoteAddress}\n`);
    }
    
  }
});

// Add new job endpoint
app.post('/job/add', async (req, res) => {
  if(req.user.type != 'employer') throw({status: 403, error: 'failed job add', reason: 'forbidden'});
  console.log('Add attempt: job');
  const newTimestamp = Math.floor(Date.now() / 1000);
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /job/add | info: add attempt: job | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  // api body MUST send null object for empty json inputs
  const {
    title,
    city,
    state,
    isRemote,
    experienceLevel,
    employmentType,
    companySize,
    salaryLow,
    salaryHigh,
    benefits,
    certifications,
    jobDescription,
    expDate,
    questions
  } = req.body;
  try {
    // check if input exists and is safe
    if(
      !title                  ||
      !city                   ||
      !state                  ||
      isRemote === undefined  ||
      !experienceLevel        ||
      !employmentType         ||
      !companySize            ||
      !salaryLow              ||
      !salaryHigh             ||
      !jobDescription         ||
      expDate === undefined
    ) {
      throw({status: 400, error: 'failed job add', reason: 'missing field'});
    }
    if(
      !validSAN(title, 255)           ||
      !validA(city, 255)              ||
      !validState(state)              ||
      !validA(experienceLevel, 255)   ||
      !validSAN(employmentType, 255)  ||
      !validSAN(companySize, 255)     ||
      !validN(salaryLow)              ||
      !validN(salaryHigh)             ||
      !validJSON(benefits)            ||
      !validJSON(certifications)      ||
      !validSAN(jobDescription, 600)  ||
      !validJSON(questions)           ||
      !validExpDate(expDate).valid    ||
      typeof(isRemote) !== 'boolean'
    ) {
      throw({status: 400, error: 'failed job add', reason: 'invalid input'});
    }
    // check if user authorized to post jobs for the company
    let check;
    try {
      check = await checkAuth(req, req.user.user_id, req.user.company);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'authorization failed'});
    }
    if(check === false) {
      throw({status: 403, error: 'failed job add', reason: 'failed approval'});
    }

    try {
      const [[employer]] = await req.db.query(`
        SELECT industry, website FROM Employer WHERE employer_id = UNHEX(:user_id);
      `,{
        user_id: req.user.user_id
      });
      const job = await req.db.query(`
        INSERT INTO Job (title, company, city, state, is_remote, industry, website, experience_level, employment_type, company_size, salary_low, salary_high, benefits, certifications, job_description, questions, employer_id, date_created, expires, date_expires)
        VALUES (:title, :company, :city, :state, :is_remote, :industry, :website, :experience_level, :employment_type, :company_size, :salary_low, :salary_high, :benefits, :certifications, :job_description, :questions, UNHEX(:employer_id), DATE_FORMAT(:date_created,'%Y-%m-%d %H:%i:%s'), :expires, DATE_FORMAT(:date_expires,'%Y-%m-%d %H:%i:%s'));
      `, {
        title: title,
        company: req.user.company,
        city: city,
        state: state,
        is_remote: isRemote,
        industry: employer.industry,
        website: employer.website,
        experience_level: experienceLevel,
        employment_type: employmentType,
        company_size: companySize,
        salary_low: salaryLow,
        salary_high: salaryHigh,
        benefits: !benefits ? null : JSON.stringify(benefits),
        certifications: !certifications ? null : JSON.stringify(certifications),
        job_description: jobDescription,
        questions: !questions ? null : JSON.stringify(questions),
        employer_id: req.user.user_id,
        date_created: newTime,
        expires: !expDate ? false : true,
        date_expires: !expDate ? null : validExpDate(expDate).expDate,
      });
      const [[jobId]] = await req.db.query(`
        SELECT job_id FROM Job 
        WHERE employer_id = UNHEX(:user_id)
        ORDER BY date_created DESC
        LIMIT 1;
      `,{
        user_id: req.user.user_id
      });
      res.status(201)
      .json({
        success: true,
        jobId: jobId.job_id
      });
      writer.write(`${setTimestamp(newTime)} | status: 201 | source: /job/add | success: ${req.user.email} @ ${req.user.company} added job id: ${jobId.job_id} | | @${req.socket.remoteAddress}\n`);
    } catch (err) {
      throw({status: 500, error: 'failed job add', reason: err.message})
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/add | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/add | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// Add resume endpoint
app.post('/resume/add', async (req, res) => {
  console.log('Add attempt: resume');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /resume/add | info: add attempt: resume | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  const {
    summary,
    education,
    experience,
    skill,
    link,
    publication,
  } = req.body;
  try {
    if(
      !summary                  ||
      education === undefined   ||
      experience === undefined  ||
      skill === undefined       ||
      link === undefined        ||
      publication === undefined
    ) {
      throw({status: 400, error: 'failed resume add', reason: 'missing field'});
    }
    if(
      !validSAN(summary, 600) ||
      !validJSON(education)   ||
      !validJSON(experience)  ||
      !validJSON(skill)       ||
      !validJSON(link)        ||
      !validJSON(publication)
    ) {
      throw({status: 400, error: 'failed resume add', reason: 'invalid input'});
    }
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed resume add', reason: check.reason});
    }
    const sqlStrs = [];
    let entries = [0,0,0,0,0]
    if(education !== null) {
      const arrEd = Object.values(education);
      let sqlStr = "INSERT INTO Education\nVALUES ";
      if(arrEd.length > 2) throw({status: 400, error: 'failed resume add', reason: 'too many education inputs'});
      let i = 0;
      const valid = arrEd.every((entry) => {
        if(
          !entry.institutionName  ||
          !entry.educationLevel   ||
          !entry.educationField   ||
          !entry.dateStart        ||
          typeof(entry.present) !== 'boolean'
        ) {return false;}
        if(
          !validSAN(entry.institutionName, 255)  ||
          !validSAN(entry.educationLevel, 255)   ||
          !validSAN(entry.educationField, 255)   ||
          !validDate(entry.dateStart)
        ) {return false;}
        if(
          (entry.dateEnd !== null && !validDate(entry.dateEnd)) ||
          (entry.dateEnd === null && entry.present === false)   ||
          (entry.dateEnd !== null && entry.present === true)
        ) {return false;}
        if((entry.dateEnd !== null && validDate(entry.dateEnd))) {
          if(!validDates(entry.dateStart, entry.dateEnd)) return false;
        }
        const dateEnd = `DATE_FORMAT("${entry.dateEnd}-01",'%Y-%m-%d')`;
        sqlStr += `(UNHEX("${req.user.user_id}"), "${entry.institutionName}", "${entry.educationLevel}", "${entry.educationField}", DATE_FORMAT('${entry.dateStart}-01','%Y-%m-%d'), ${!entry.dateEnd ? null : dateEnd}, ${entry.present})`;
        if(i < arrEd.length - 1) {
          sqlStr += ',\n';
          i++;
        }
        return true;
      });
      if(!valid) throw({status: 400, error: 'failed resume add', reason: 'invalid education input'});
      sqlStr += ";";
      entries[0] = arrEd.length;
      sqlStrs.push(sqlStr);
    }
    if(experience !== null) {
      const arrEx = Object.values(experience);
      let sqlStr = "INSERT INTO Experience\nVALUES ";
      if(arrEx.length > 3) throw({status: 400, error: 'failed resume add', reason: 'too many experience inputs'});
      let i = 0;
      const valid = arrEx.every((entry) => {
        if(
          !entry.jobTitle                     ||
          !entry.companyName                  ||
          !entry.city                         ||
          !entry.state                        ||
          !entry.dateStart                    ||
          typeof(entry.remote) !== 'boolean'  ||
          typeof(entry.present) !== 'boolean'
        ) {return false;}
        if(
          !validSAN(entry.jobTitle, 255)    ||
          !validSAN(entry.companyName, 255) ||
          !validSAN(entry.city, 255)        ||
          !validState(entry.state)          ||
          !validDate(entry.dateStart)
        ) {return false;}
        if((entry.dateEnd !== null && !validDate(entry.dateEnd))  ||
          (entry.dateEnd === null && entry.present === false)     ||
          (entry.dateEnd !== null && entry.present === true)      ||
          (entry.address === null && entry.remote === false)      ||
          (entry.address !== null && entry.remote === true)       ||
          (entry.jobDescription !== null && !validSAN(entry.jobDescription))
        ) {return false;}
        if((entry.dateEnd !== null && validDate(entry.dateEnd))) {
          if(!validDates(entry.dateStart, entry.dateEnd)) return false;
        }
        const jobDescription = `"${entry.jobDescription}"`;
        const address = `"${entry.address}"`;
        const dateEnd = `DATE_FORMAT("${entry.dateEnd}-01",'%Y-%m-%d')`;
        sqlStr += `(UNHEX("${req.user.user_id}"), "${entry.jobTitle}", "${entry.companyName}", ${entry.remote}, ${!entry.address ? null : address}, "${entry.city}", "${entry.state}", DATE_FORMAT("${entry.dateStart}-01",'%Y-%m-%d'), ${!entry.dateEnd ? null : dateEnd}, ${entry.present}, ${!entry.jobDescription ? null : jobDescription})`;
        if(i < arrEx.length - 1) {
          sqlStr += ',\n';
          i++;
        }
        return true;
      });
      if(!valid) throw({status: 400, error: 'failed resume add', reason: 'invalid experience input'});
      sqlStr += ";";
      entries[1] = arrEx.length;
      sqlStrs.push(sqlStr);
    }
    if(skill !== null) {
      const arrSk = Object.values(skill);
      let sqlStr = "INSERT INTO Skill\nVALUES ";
      if(arrSk.length > 25) throw({status: 400, error: 'failed resume add', reason: 'too many skill inputs'});
      let i = 0;
      const valid = arrSk.every((entry) => {
        if(
          !entry.skillName  ||
          !entry.skillYears
        ) {return false;}
        if(
          !validSAN(entry.skillName, 255)  ||
          !validN(entry.skillYears)
        ) {return false;}
        if(entry.skillName.length > 255 || entry.skillYears > 50 || entry.skillYears < 1) {
          return false;
        }
        sqlStr += `(UNHEX("${req.user.user_id}"), "${entry.skillName}", ${entry.skillYears})`;
        if(i < arrSk.length - 1) {
          sqlStr += ',\n';
          i++;
        }
        return true;
      });
      if(!valid) throw({status: 400, error: 'failed resume add', reason: 'invalid link input'});
      sqlStr += ";";
      entries[2] = arrSk.length;
      sqlStrs.push(sqlStr);
    }
    if(link !== null) {
      const arrLk = Object.values(link);
      let sqlStr = "INSERT INTO Url\nVALUES ";
      if(arrLk.length > 5) throw({status: 400, error: 'failed resume add', reason: 'too many link inputs'});
      let i = 0;
      const valid = arrLk.every((entry) => {
        if(
          !entry.linkName ||
          !entry.linkUrl
        ) {return false;}
        if(
          !validSAN(entry.linkName, 255) ||
          !validSAN(entry.linkUrl, 2047)
        ) {return false;}
        if(entry.linkName.length > 255 || entry.linkUrl.length > 2048) {
          return false;
        }
        sqlStr += `(UNHEX("${req.user.user_id}"), "${entry.linkName}", "${entry.linkUrl}")`;
        if(i < arrLk.length - 1) {
          sqlStr += ',\n';
          i++;
        }
        return true;
      });
      if(!valid) throw({status: 400, error: 'failed resume add', reason: 'invalid link input'});
      sqlStr += ";";
      entries[3] = arrLk.length;
      sqlStrs.push(sqlStr);
    }
    if(publication !== null) {
      const arrPub = Object.values(publication);
      let sqlStr = "INSERT INTO Publication\nVALUES ";
      if(arrPub.length > 5) throw({status: 400, error: 'failed resume add', reason: 'too many link inputs'});
      let i = 0;
      const valid = arrPub.every((entry) => {
        if(
          !entry.pubName    ||
          !entry.pubUrl     ||
          !entry.pubDate    ||
          !entry.pubSummary
        ) {return false;}
        if(
          !validSAN(entry.pubName, 255) ||
          !validSAN(entry.pubUrl, 2047) ||
          !validDate(entry.pubDate)     ||
          !validSAN(entry.pubSummary, 600)
        ) {return false;}
        if(entry.pubName.length > 255 || entry.pubUrl.length > 2048) {
          return false;
        }
        const jobDescription = `"${entry.jobDescription}"`;
        const address = `"${entry.address}"`;
        const dateEnd = `DATE_FORMAT("${entry.dateEnd}-01",'%Y-%m-%d')`;
        sqlStr += `(UNHEX("${req.user.user_id}"), "${entry.pubName}", "${entry.pubUrl}", DATE_FORMAT("${entry.pubDate}-01",'%Y-%m-%d'), "${entry.pubSummary}")`;
        if(i < arrPub.length - 1) {
          sqlStr += ',\n';
          i++;
        }
        return true;
      });
      if(!valid) throw({status: 400, error: 'failed resume add', reason: 'invalid publication input'});
      sqlStr += ";";
      entries[4] = arrPub.length;
      sqlStrs.push(sqlStr);
    }
    await req.db.execute(`
      DELETE
        FROM Education, Experience, Skill, Url, Publication
        USING Education, Experience, Skill, Url, Publication
        WHERE (Education.seeker_id = UNHEX(:user_id) AND Experience.seeker_id = UNHEX(:user_id) AND Skill.seeker_id = UNHEX(:user_id) AND Url.seeker_id = UNHEX(:user_id) AND Publication.seeker_id = UNHEX(:user_id));
    `,{
      user_id: req.user.user_id,
    });
    sqlStrs.push(`UPDATE Seeker\nSET summary = '${summary}', education_entries = ${entries[0]}, experience_entries = ${entries[1]}, skill_entries = ${entries[2]}, link_entries = ${entries[3]}, publication_entries = ${entries[4]}\nWHERE seeker_id = UNHEX("${req.user.user_id}");`);
    sqlStrs.every(async (entry) => await req.db.execute(entry));
    writer.write(`${setTimestamp(newTime)} | status: 201 | source: /resume/add | success: ${req.user.email} added/updated resume | | @${req.socket.remoteAddress}\n`);
    res.status(201).json({success: true, message: "resume info added"});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /resume/add | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /resume/add | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.get('/resume', async (req, res) => {
  console.log('Get attempt: resume');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /resume | info: get attempt: resume | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  try{
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed resume add', reason: check.reason});
    }
    try {
      const [[seeker]] = await req.db.query(`
        SELECT first_name, last_name, email, summary
        FROM Seeker
        WHERE seeker_id = UNHEX(:user_id);
        `, {
          user_id: req.user.user_id,
      });
      const [education] = await req.db.query(`
        SELECT institution_name, education_level, education_field, date_start, date_end, present
        FROM Education
        WHERE seeker_id = UNHEX(:user_id);
        `, {
          user_id: req.user.user_id,
      });const [experience] = await req.db.query(`
        SELECT job_title, company_name, address, city, state, date_start, date_end,  present, remote, job_description
        FROM Experience
        WHERE seeker_id = UNHEX(:user_id);
        `, {
          user_id: req.user.user_id,
      });
      const [skill] = await req.db.query(`
        SELECT skill_name, skill_years
        FROM Skill
        WHERE seeker_id = UNHEX(:user_id);
        `, {
          user_id: req.user.user_id,
      });
      const [link] = await req.db.query(`
        SELECT link_name, link_url
        FROM Url
        WHERE seeker_id = UNHEX(:user_id);
        `, {
          user_id: req.user.user_id,
      });
      const [publication] = await req.db.query(`
        SELECT publication_name, publication_url, publication_date, publication_summary
        FROM Publication
        WHERE seeker_id = UNHEX(:user_id);
        `, {
          user_id: req.user.user_id,
      });
      const response = {success: true};
      response.seeker = seeker;
      response.education = !education.length ? null : education;
      response.experience = !experience.length ? null : experience;
      response.skill = !skill.length ? null : skill;
      response.link = !link.length ? null : link;
      response.publication = !publication.length ? null : publication;
      writer.write(`${setTimestamp(newTime)} | status: 200 | source: /resume | success: get attempt: resume | | @${req.socket.remoteAddress}\n`);
      res.status(200).json(response)
    } catch (err) {
      console.warn(err);
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /resume | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /resume | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});


app.post('/job/apply/:job_id/submit', async (req, res) => {
  console.log('add attempt: application');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /job/apply | info: add attempt: application | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  const {answers} = req.body;
  const job_id = parseInt(req.params.job_id);
  try{
    if(!job_id) {
      throw({status: 400, error: 'failed application add', reason: 'missing field'});
    }
    if(!validN(job_id) || !validJSON(answers)) {
      throw({status: 400, error: 'failed application add', reason: 'invalid input'});
    }
    let questions;
    let employer;
    let title;
    try {
      [[{questions, employer, title}]] = await req.db.query(`
        SELECT questions, HEX(employer_id) AS employer, title
        FROM Job
        WHERE job_id = :job_id;
        `,{
          job_id: job_id,
      });
    } catch (err) {
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
    //questions = questions.questions;
    if(!questions && answers) {
      throw({status: 400, error: 'failed application add', reason: 'answers with no questions'});
    }
    if(questions !== null){
      if(!answers || Object.keys(answers).length < Object.keys(questions).length) throw({status: 400, error: 'failed application add', reason: 'unanswered questions'});
      if(Object.keys(answers).length > Object.keys(questions).length) throw({status: 400, error: 'failed application add', reason: 'too many answers'});
    }
    let repeat;
    try {
      [[repeat]] = await req.db.query(`
        SELECT CASE
        WHEN EXISTS (
          SELECT 1 FROM Application
          WHERE (job_id = :job_id AND seeker_id = UNHEX(:seeker_id))
        )
        THEN (
          SELECT job_id FROM Application
          WHERE (job_id = :job_id AND seeker_id = UNHEX(:seeker_id))
        )
        ELSE NULL
        END AS job_id
        FROM Application;
      `,{
        job_id: job_id,
        seeker_id: req.user.user_id,
      });
      repeat = !repeat.job_id ? false : true;
    } catch (err) {
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
    if(repeat) {
      throw({status: 400, error: 'failed application add', reason: 'already applied'});
    }
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed application add', reason: check.reason});
    }
    try {
      await req.db.query(`
        INSERT INTO Application(seeker_id, job_id, answers)
        VALUE(UNHEX(:seeker_id), :job_id, :answers);
      `, {
        seeker_id: req.user.user_id,
        job_id: job_id,
        answers: !answers ? null : JSON.stringify(answers),
      });
      const [[{email}]] = await req.db.query(`
        SELECT email
        FROM Employer
        WHERE employer_id = UNHEX(:employer_id);
      `,{
        employer_id: employer,
      });
      const [[{first_name, last_name}]] = await req.db.query(`
        SELECT first_name, last_name
        FROM Seeker
        WHERE seeker_id = UNHEX(:seeker_id);
      `,{
        seeker_id: req.user.user_id,
      });
      await sendApplication(email, {title: title}, {first_name: first_name, last_name: last_name});
      writer.write(`${setTimestamp(newTime)} | status: 201 | source: /job/apply | success: application added | | @${req.socket.remoteAddress}\n`);
      res.status(201).json({success: true, message: 'application submitted'})
    } catch (err) {
      console.warn(err);
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /resume | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /resume | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.get('/job/applied', async (req, res) => {
  console.log('Get attempt: jobs applied');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /job/applied | info: get attempt: jobs applied | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  try{
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed jobs applied get', reason: check.reason});
    }
    try {
      const [apps] = await req.db.query(`
        SELECT title, date_applied, questions, answers, seen, accepted, rejected
        FROM Application INNER JOIN Job
        ON Job.job_id = Application.job_id
        WHERE (Application.seeker_id = UNHEX(:user_id) AND Job.delete_flag = 0)
        ORDER BY date_applied DESC;
      `, {
        user_id: req.user.user_id,
      });
      console.log(apps)
      const response = {success: true};
      response.apps = apps;
      //writer.write(`${setTimestamp(newTime)} | status: 200 | source: /job/applied | success: get attempt: jobs applied | | @${req.socket.remoteAddress}\n`);
      res.status(200).json(response)
    } catch (err) {
      console.warn(err);
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/applied | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/applied | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.get('/job/applications', async (req, res) => {
  console.log('Get attempt: applications');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /job/applications | info: get attempt: applications | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  const start_index = parseInt(req.query.startIndex);
  const per_page = parseInt(req.query.perPage);
  try{
    if(!validN(start_index) || !validN(per_page)) {
      throw({status:400, error: 'failed applications get', reason: 'invalid query'});
    }
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 400, error: 'failed application get', reason: check.reason});
    }
    let auth;
    try {
      auth = await checkAuth(req, req.user.user_id, req.user.company);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'authorization failed'});
    }
    if(auth === false) {
      throw({status: 403, error: 'failed application get', reason: 'failed approval'});
    }
    try {
      const [apps] = await req.db.query(`
        SELECT HEX(Seeker.seeker_id) AS user_id, email, Job.job_id, app_index, title, first_name, last_name, seen, accepted, rejected
        FROM Application INNER JOIN (Seeker, Job)
        ON (Seeker.seeker_id = Application.seeker_id AND Job.job_id = Application.job_id)
        WHERE (Job.company = :company AND Seeker.delete_flag = 0 AND Job.delete_flag = 0 AND app_index > :start_index)
        ORDER BY date_applied DESC
        LIMIT :per_page;
      `, {
        company: req.user.company,
        start_index: start_index,
        per_page: per_page,
      });
      console.log(apps)
      const response = {success: true};
      response.apps = apps;
      //writer.write(`${setTimestamp(newTime)} | status: 200 | source: /resume | success: get attempt: resume | | @${req.socket.remoteAddress}\n`);
      res.status(200).json(response)
    } catch (err) {
      console.warn(err);
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/applications | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/applications | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.get('/job/applications/resume', async (req, res) => {
  console.log('Get attempt: applicant resume');
  const newTime = new Date(Date.now());// for logging
  const resumeEmail = req.query.email;
  const app_index = parseInt(req.query.appIndex);
  writer.write(`${setTimestamp(newTime)} | | source: /job/applications/resume | info: get attempt: applicant resume | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  try{
    if(!validSAN(resumeEmail) || !validN(app_index)) {
      throw({status:400, error: 'failed applicant resume get', reason: 'invalid query'});
    }
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 404, error: 'failed applicant resume get', reason: check.reason});
    }
    let auth;
    try {
      auth = await checkAuth(req, req.user.user_id, req.user.company);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'authorization failed'});
    }
    if(auth === false) {
      throw({status: 403, error: 'failed applicant resume get', reason: 'failed approval'});
    }
    let applicant;
    try {
      applicant = await checkUser(req, resumeEmail);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'failed to find applicant'});
    }
    if(applicant.exists === false) {
      throw({status: 404, error: 'failed applicant resume get', reason: seeker.reason});
    }
    try {
      const [[{resume_uploaded}]] = await req.db.query(`
        SELECT CASE
          WHEN EXISTS(SELECT 1
            FROM Application INNER JOIN (Seeker, Job)
            ON (Seeker.seeker_id = Application.seeker_id AND Job.job_id = Application.job_id)
            WHERE (Application.seeker_id = UNHEX(:seeker_id) AND Job.company = :company))
          THEN(SELECT resume_uploaded
            FROM Seeker
            WHERE seeker_id = UNHEX(:seeker_id))
          ELSE NULL
        END AS resume_uploaded;
      `, {
        company: req.user.company,
        seeker_id: applicant.userId,
      });
      const resume = {};
      if(resume_uploaded === 0) {
        const [[seeker]] = await req.db.query(`
          SELECT first_name, last_name, email, summary
          FROM Seeker
          WHERE seeker_id = UNHEX(:user_id);
          `, {
            user_id: applicant.userId,
        });
        const [education] = await req.db.query(`
          SELECT institution_name, education_level, education_field, date_start, date_end, present
          FROM Education
          WHERE seeker_id = UNHEX(:user_id);
          `, {
            user_id: applicant.userId,
        });const [experience] = await req.db.query(`
          SELECT job_title, company_name, address, city, state, date_start, date_end,  present, remote, job_description
          FROM Experience
          WHERE seeker_id = UNHEX(:user_id);
          `, {
            user_id: applicant.userId,
        });
        const [skill] = await req.db.query(`
          SELECT skill_name, skill_years
          FROM Skill
          WHERE seeker_id = UNHEX(:user_id);
          `, {
            user_id: applicant.userId,
        });
        const [link] = await req.db.query(`
          SELECT link_name, link_url
          FROM Url
          WHERE seeker_id = UNHEX(:user_id);
          `, {
            user_id: applicant.userId,
        });
        const [publication] = await req.db.query(`
          SELECT publication_name, publication_url, publication_date, publication_summary
          FROM Publication
          WHERE seeker_id = UNHEX(:user_id);
          `, {
            user_id: applicant.userId,
        });
        resume.success = true;
        resume.seeker = seeker;
        resume.education = !education.length ? null : education;
        resume.experience = !experience.length ? null : experience;
        resume.skill = !skill.length ? null : skill;
        resume.link = !link.length ? null : link;
        resume.publication = !publication.length ? null : publication;
      } else if(resume_uploaded === 1) {
        const [[{resume_url}]] = await req.db.query(`
          SELECT resume_url
          FROM Seeker INNER JOIN Application
          ON Seeker.seeker_id = Application.seeker_id
          WHERE Application.seeker_id = UNHEX(:seeker_id);
          `,{
            seeker_id: applicant.userId,
        });
        resume.success = true;
        resume.resume_url = resume_url
      } else {
        throw({message: "null where field set to default false"})
      }
      await req.db.query(`
        UPDATE Application
        SET Seen = 1
        WHERE app_index = :app_index;
      `,{
        app_index: app_index,
      })
      writer.write(`${setTimestamp(newTime)} | status: 200 | source: /job/applications/resume | success: get attempt: applicant resume | | @${req.socket.remoteAddress}\n`);
      res.status(200).json(resume)
    } catch (err) {
      console.warn(err);
      throw({status:500, error: err.message, reason: 'MySQL error'});
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/applications/resume | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/applications | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.get('/delete-user', async (req, res) => {
  console.log('Delete request');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /delete-user | info: delete request | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  const payload = {
    user_id: req.user.user_id,
    type: req.user.type,
    deleter: "yes please",
    exp: timeNow + (60 * 10) 
  }
  try {
    const token = jwt.sign(payload, process.env.JWT_KEY);
    await sendDelete(req.user.email, token);
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /delete-user | success: email sent | | ${req.user.email}@${req.socket.remoteAddress}\n`);

    res.status(200).json({ success: true, message: 'delete link sent to email'});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /delete-user | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /delete-user | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
})

app.delete('/delete', async (req, res) => {
  console.log('Delete request');
  //const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | | source: /delete | info: delete ${req.user.email} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  const token = req.query.token;

  try {
    const {user_id, type, deleter} = jwt.verify(token, process.env.JWT_KEY);
    if(deleter !== 'yes please' || !user_id || !validA(type)) {
      throw({status: 404, error: 'failed user deletion', reason: 'invalid token'});
    }
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 404, error: 'failed user deletion', reason: check.reason});
    }
    try {
      const deleted = await req.db.query(`
        UPDATE ${type}
        SET delete_flag = 1
        WHERE ${type}_id = UNHEX(:user_id);
      `,{
        user_id: user_id
      });
      writer.write(`${setTimestamp(newTime)} | status: 200 | source: /delete | success: user deleted | | ${req.user.email}@${req.socket.remoteAddress}\n`);
  
      res.status(200).json({ success: true, message: 'deleted user'});
    } catch (err) {
      throw({status: 500, error: err.message, reason: 'deletion failed'});
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /delete-user | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /delete-user | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.delete('/job/delete', async (req, res) => {
  console.log('Delete request');
  //const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());// for logging
  const job_id = req.query.id;
  writer.write(`${setTimestamp(newTime)} | | source: /job/delete | info: delete ${job_id} requested | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
  try {
    let check;
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'check failed'});
    }
    if(check.exists === false) {
      throw({status: 404, error: 'failed job deletion', reason: check.reason});
    }
    let auth;
    try {
      auth = await checkAuth(req, req.user.user_id, req.user.company, job_id);
    } catch (err) {
      throw({status:500, error: err.message, reason: 'authorization failed'});
    }
    if(auth === false) {
      throw({status: 403, error: 'failed job deletion', reason: 'failed approval'});
    }
    await req.db.query(`
      UPDATE Job
      SET delete_flag = 1
      WHERE job_id = UNHEX(:job_id);
    `,{
      job_id: job_id
    })
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/delete | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /job/delete | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});





























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
    const [seeker] = await req.db.query(
      `SELECT first_name, last_name FROM seeker WHERE seeker_id = UNHEX(:seeker_id)`,
      {
        seeker_id: seeker_id,
      }
    );
    res.status(200).json(seeker[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to get seeker" });
  }
});
//fetch user from employer table
app.get("/employer", async (req, res) => {
  const employer_id = req.user.user_id;
  const email = req.user.email;

  if (!employer_id) {
    return res.status(400).json({ error: "Missing employer_id" });
  }

  try {
    let check;
    check = await checkUser(req, email);
    if (check.exists == false) {
      throw {
        status: 400,
        error: "failed to get employer",
        reason: "user not found",
      };
    }
    const [employer] = await req.db.query(
      `SELECT first_name, last_name FROM employer WHERE employer_id = UNHEX(:employer_id)`,
      {
        employer_id: employer_id,
      }
    );
    res.status(200).json(employer[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to get employer" });
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
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /saved-jobs | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /saved-jobs | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

//remove job
app.delete("/saved-jobs/:jobId", async (req, res) => {
  const seeker_id = req.user.user_id;
  const jobId = req.params.jobId;
  writer.write(`${setTimestamp(newTime)} | | source: /saved-jobs/${jobId} | info: delete saved job attempt | | ${req.user.email}@${req.socket.remoteAddress}\n`);
  
  try {
    if (!seeker_id || !jobId) {
      throw({status: 400, error: 'failed to delete saved job', reason: 'invalid input'});
    }
    const [result] = await req.db.query(
      `DELETE FROM saved_job WHERE seeker_id = UNHEX(:seeker_id) AND job_id = :jobId`,
      {
        seeker_id: seeker_id,
        jobId: jobId,
      }
    );

    if (result.affectedRows === 0) {
      throw({status: 404, error: 'failed to delete saved job', reason: 'job not found'});
    }
    
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /saved-jobs/${jobId} | success: deleted saved job | | ${req.user.email}@${req.socket.remoteAddress}\n`);
    res.status(200).json({ message: "Job removed successfully" });
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /saved-jobs/${jobId} | error: ${err.message} | | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /saved-jobs/${jobId} | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

//add a logout endpoint
app.post("/logout", (req, res) => {
  const newTime = new Date(Date.now()); // for logging
  writer.write(`${setTimestamp(newTime)} | | source: /logout | info: logout attempt | | ${req.user.email}@${req.socket.remoteAddress}\n`);
  
  // Clear client-side data instructions.
  res.status(200).json({ success: true, message: "Logout successful. Please clear your token from the client." });
  writer.write(`${setTimestamp(newTime)} | status: 200 | source: /logout | success: user logged out | | ${req.user.email}@${req.socket.remoteAddress}\n`);
});

app.listen(port, () => {
  console.log(`server started on http://localhost:${port} @ ${time}`);
  writer.write(`${setTimestamp(time)} | port: ${port} | server started\n`)
});
