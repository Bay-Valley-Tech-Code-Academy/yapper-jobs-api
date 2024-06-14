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
require('dotenv').config();



const time = new Date(Date.now());// used to log server start
const writer = fs.createWriteStream('../ape.log', {flags: 'a'});// open log for appending, creates file if it does not exist

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
    writer.write(`${setTimestamp(newTime)} | status: 429 | source: /login | error: Too Many Requests | ${req.body.email}@${req.socket.remoteAddress}\n`);
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
    writer.write(`${setTimestamp(newTime)} | status: 429 | source: /register | error: Too Many Requests | ${req.body.email}@${req.socket.remoteAddress}\n`);
    res.status(429).json({success: false, error: 'Too Many Requests'});
  }
});

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

// Register endpoint for job seeker
app.post('/register/seeker', async (req, res) => {
  console.log('registration attempt: seeker');
  const timeNow = Math.ceil(Date.now() / 1000);// for jwt expiration
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | Registration attempt: seeker\n`);
  const {
    firstName,
    lastName,
    pass,
    email
  } = req.body;
  try {
    // check if input exists and is safe
    if(firstName == null || lastName == null || pass == null || email == null) {
      throw({status: 400, error: 'failed seeker add', reason: 'missing field'});
    }
    if(!validSAN(firstName) || !validSAN(lastName) || !validSAN(pass) || !validSAN(email)) {
      throw({status: 400, error: 'failed seeker add', reason: 'invalid input'});
    }
    // check if user or email already exists
    let check;
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw({status:500, error: err, reason: 'check failed'});
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
          firstName: users.first_name,
          lastName: users.last_name,
          email: users.email,
          jwt: users.jwt
        });
        writer.write(`${setTimestamp(newTime)} | status: 201 | source: /register/seeker | success: job seeker added | ${email}@${req.socket.remoteAddress}\n`);
      } catch (err) {
        res.status(500).json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/seeker bcrypt\.then | error: ${err} | attempt: ${email}@${req.socket.remoteAddress}\n`);
      }});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/seeker | error: ${err} | @${req.socket.remoteAddress}\n`);
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
  writer.write(`${setTimestamp(newTime)} | registration attempt: employer\n`);
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
  try {
    let check;
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
    try {
      check = await checkUser(req, email);
    } catch (err) {
      throw({status:500, error: err, reason: 'check failed'});
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
        
        res.status(200)
        .json({
          success: true,
          firstName: users.firstName,
          lastName: users.lastName,
          email: users.email,
          company: users.company,
          jwt: users.jwt
        });
        console.log('USER', user);
        writer.write(`${setTimestamp(newTime)} | status: 201 | source: /register/employer | success: employer ${email} @ ${company} added | @${req.socket.remoteAddress}\n`);
      } catch (err) {
        res.status(500).json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/employer bcrypt\.then | error: ${err} | attempt: ${email}@${req.socket.remoteAddress}\n`);
      }});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/employer | error: ${err} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /register/employer | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n\n`);
    }
  }
});

// Login endpoint for job seeker
app.post('/login/seeker', async (req, res) => {
  console.log('login attempt: seeker');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | login attempt: seeker\n`);
  const {email, pass} = req.body;
  try {
    let check;
    if(!email || !pass) {
      throw({status: 400, error: 'failed seeker login', reason: 'missing field'});
    }
    if(!validSAN(email) || !validSAN(pass)) {
      throw({status: 400, error: 'failed seeker login', reason: 'invalid input'});
    }
    check = await checkUser(req, email);
    if(check.exists === false) {
      throw({status: 400, error: 'failed seeker login', reason: 'user not found'});
    }
    const [[users]] = await req.db.query(`SELECT :first_name, :last_name, user_pass, email, hex(seeker_id) AS user_id FROM Seeker
      WHERE (email = :email AND delete_flag = 0);`,
      {email: email}
    );
    if (!users) {
      throw({status: 500, error: 'failed login', reason: 'user does not exist'});
    }
    const dbPassword = `${users.user_pass}`;
    const compare = await bcrypt.compare(pass, dbPassword);
    if(!compare) {
      throw({status: 400, error: 'failed login',reason: 'incorrect password'});
    }
    const payload = {
      user_id: users.user_id,
      // firstName: users.first_name,
      // lastName: users.last_name,
      email: users.email,
      exp: timeNow + (60 * 60 * 24 * 7 * 2)
    }
    
    const encodedUser = jwt.sign(payload, process.env.JWT_KEY);
    
    res.status(200)
    .json({
      success: true, 
      firstName: users.firstName,
      lastName: users.lastName,
      email: users.email,
      jwt: encodedUser
    });
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /login/seeker | login: seeker ${email} logged in | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /login/seeker | error: ${err} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /login/seeker | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// Login endpoint for employer
app.post('/login/employer', async (req, res) => {
  console.log('login attempt: employer');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | login attempt: employer\n`);
  const {email, pass} = req.body;
  try {
    let check;
    if(!email || !pass) {
      throw({status: 400, error: 'failed employer login', reason: 'missing field'});
    }
    if(
      !validSAN(email) ||
      !validSAN(pass)
    ) {
      throw({status: 400, error: 'failed employer login', reason: 'invalid input'});
    }
    check = await checkUser(req, email, `employer`);
    if(check.exists == false) {
      throw({status: 400, error: 'failed employer login', reason: 'user not found'});
    }
    const users = await login(req, email, pass);
    
    res.status(200).json({
      success: true,
      firstName: users.firstName,
      lastName: users.lastName,
      email: users.email,
      company: users.company,
      jwt: users.jwt});
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /login/employer | success: ${users.email} @ ${users.company} logged in | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /login/employer | error: ${err} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /login/employer | error: ${err.error} | reason: ${err.reason} | attempt: ${email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// JWT verification checks to see if there is an authorization header with a valid JWT in it.
app.use(async function verifyJwt(req, res, next) {
  console.log('Verify attempt: JWT');
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | verify attempt: JWT | attempt: @${req.socket.remoteAddress}\n`);
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
      const payload = jwt.verify(token, process.env.JWT_KEY);
      req.user = payload;
      writer.write(`${setTimestamp(newTime)} | Verified: JWT | ${req.user.email}@${req.socket.remoteAddress}\n`)
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
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: JWT | error: ${err} | @${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: JWT | error: ${err.error} | reason: ${err.reason} | @${req.socket.remoteAddress}\n`);
    }
    
  }
  

});

// Add new job endpoint
app.post('/job/add', async (req, res) => {
  console.log('Add attempt: job');
  const newTimestamp = Math.floor(Date.now() / 1000);
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | add attempt: job | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
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
      !validN(companySize)            ||
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
      throw({status:500, error: err, reason: 'authorization failed'});
    }
    if(check === false) {
      throw({status: 500, error: 'failed job add', reason: 'failed approval'});
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
        benefits: benefits,
        certifications: certifications,
        job_description: jobDescription,
        questions: questions,
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
      res.status(200)
      .json({
        success: true,
        jobId: jobId.job_id
      });
      writer.write(`${setTimestamp(newTime)} | status: 201 | source: /job/add | success: ${req.user.email} @ ${req.user.company} added job id: ${jobId.job_id} | @${req.socket.remoteAddress}\n`);
    } catch (err) {
      throw({status: 500, error: 'failed job add', reason: err.message})
    }
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /job/add | error: ${err.message} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
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
  writer.write(`${setTimestamp(newTime)} | add attempt: resume | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
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
    try {
      check = await checkUser(req, req.user.email);
    } catch (err) {
      throw({status:500, error: err, reason: 'check failed'});
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
    res.json({message: "wow"})
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /resume/add | error: ${err.message} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /resume/add | error: ${err.error} | reason: ${err.reason} | attempt: ${req.user.email}@${req.socket.remoteAddress}\n`);
    }
  }
});

// from here

app.listen(port, () => {
  console.log(`server started on http://localhost:${port} @ ${time}`);
  writer.write(`${setTimestamp(time)} | port: ${port} | server started\n`)
});