const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
require('dotenv').config();

const time = new Date(Date.now());// used to log server start
const writer = fs.createWriteStream('express/ape.log', {flags: 'a'});// open log for appending, creates file if it does not exist

const app = express();
const port = process.env.PORT; // default port

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
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
      check = await checkUser(req, email, `seeker`);
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
      !validSAN(firstName) ||
      !validSAN(lastName) ||
      !validSAN(pass) ||
      !validSAN(email) ||
      !validSAN(mobile) ||
      !validSAN(company) ||
      !validSAN(website) ||
      !validSAN(industry)
    ) {
      throw({status: 400, error: 'failed employer add', reason: 'invalid input'});
    }
    try {
      check = await checkUser(req, email, `employer`, company);
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
    check = await checkUser(req, email, `seeker`);
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
      firstName: users.first_name,
      lastName: users.last_name,
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
    const users = await login(req, email, pass, 'employer');
    
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

// Check if user already exists for that type of user
async function checkUser(req, email, table) {
  const newTime = new Date(Date.now());
  try {
    let check;
    if(table == 'seeker'){
      const [[sql]] = await req.db.query(`
        SELECT CASE 
          WHEN EXISTS(SELECT 1 FROM Seeker WHERE email = :email)
            THEN (SELECT delete_flag FROM Seeker WHERE email = :email AND delete_flag = 0)
          ELSE null
          END AS checked
        FROM Seeker LIMIT 1;`,
        {email: email}
      );
      check = sql;
    } else if (table == 'employer'){
      const [[sql]] = await req.db.query(`
        SELECT CASE 
          WHEN EXISTS(SELECT 1 FROM Employer WHERE email = :email)
            THEN (SELECT delete_flag FROM Employer WHERE email = :email AND delete_flag = 0)
          ELSE null
          END AS checked
        FROM Seeker LIMIT 1;`,
        {email: email}
      );
      check = sql;
    } else {
      throw('Not a valid check');
    }
    switch (check.checked) {// query return logic
      case 0:
        return {exists: true, reason: 'email already registered'};
      case 1:
        return {exists: false, reason: null};
      case null:
        return {exists: false, reason: null};
      default:
        throw('unexpected value returned while searching');
    }
  } catch(err) {
      console.warn(err);
      writer.write(`${setTimestamp(newTime)} | error: ${err}\n`);
      return err;
  }
}

async function login(req, email, pass, table) {
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  try {
    let users;
    if(table == 'seeker'){
      const [[response]] = await req.db.query(`
        SELECT first_name, last_name, user_pass, email, hex(seeker_id) AS user_id FROM Seeker
          WHERE (email = :email AND delete_flag = 0);`,
        {email: email}
      );
      users = response;
    } else if (table == 'employer'){
      const [[response]] = await req.db.query(`
        SELECT first_name, last_name, user_pass, email, company, hex(employer_id) AS user_id FROM Employer
          WHERE (email = :email AND delete_flag = 0);`,
        {email: email}
      );
      users = response;
    } else {
      throw({status: 500, error: 'failed login', reason: 'user logging in'});
    }
    if (!users) {
      throw({status: 500, error: 'failed login', reason: 'user not found'});
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
      // company: !company ? null : company,
      type: table,
      exp: timeNow + (60 * 60 * 24 * 7 * 2)
    }
    const encodedUser = jwt.sign(payload, process.env.JWT_KEY);
    return {
      firstName: users.first_name,
      lastName: users.last_name,
      email: users.email,
      company: !users.company ? null : users.company,
      jwt: encodedUser
    }
  } catch(err) {
      console.warn(err);
      writer.write(`${setTimestamp(newTime)} | error: ${err}\n`);
      return err;
  }
  /* const [[users]] = await req.db.query(`SELECT  :first_name, :last_name, user_pass, email, hex(seeker_id) AS user_id FROM Seeker
    WHERE (email = :email AND delete_flag = 0);`,
    {email: email}
  ); */
}

function logger(writeOut, newTime, address, source, user) {
  writer.write(`${setTimestamp(newTime)} | status: ${writeOut.status != null ? writeOut.status : 500} | source: ${source} | error: ${writeOut.error} | reason: ${writeOut.reason} | user: ${user}@${address}\n`);
}

function errLogger(errOut, newTime, address, source, user) {
  writer.write(`${setTimestamp(newTime)} | status: ${errOut.status != null ? errOut.status : 500} | source: ${source} | error: ${errOut.error} | reason: ${errOut.reason} | user: ${user}@${address}\n`);
}

// Human readable timestamp for log
function setTimestamp(timeUpdate) {
  const months = (timeUpdate.getMonth() < 10) ? '0' + timeUpdate.getMonth() : timeUpdate.getMonth();
  const days = (timeUpdate.getDate() < 10) ? '0' + timeUpdate.getDate() : timeUpdate.getDate();
  const hours = (timeUpdate.getHours() < 10) ? '0' + timeUpdate.getHours() : timeUpdate.getHours();
  const minutes = (timeUpdate.getMinutes() < 10) ? '0' + timeUpdate.getMinutes() : timeUpdate.getMinutes();
  const seconds = (timeUpdate.getSeconds() < 10) ? '0' + timeUpdate.getSeconds() : timeUpdate.getSeconds();
  const formatted = timeUpdate.getFullYear() + '-' + months + '-' + days + ' ' + hours + ':' + minutes + ':' + seconds;
  return formatted;
}

// validate input
// alphanumeric
function validAN(check) {
  const pattern = /^[A-Za-z0-9]+$/g;
  const checked = pattern.test(check);
  return checked;
}
// special characters + alphanumeric
function validSAN(check) {
  const pattern = /^[A-Za-z0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
  const checked = pattern.test(check);
  return checked;
}

app.listen(port, () => {
  console.log(`server started on http://localhost:${port} @ ${time}`);
  writer.write(`${setTimestamp(time)} | port: ${port} | server started\n`)
});
