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
  const newTime = new Date(Date.now());// for logging
  writer.write(`${setTimestamp(newTime)} | Registration attempt: seeker\n`);
  const {
    username,
    pass,
    email
  } = req.body;
  try {
    // check if input exists and is safe
    if(username == null || pass == null || email == null) {
      throw({status: 400, error: 'failed seeker add', reason: 'missing field'});
    }
    if(!validSAN(username) || !validSAN(pass) || !validSAN(email)) {
      throw({status: 400, error: 'failed employer add', reason: 'invalid input'});
    }
    // check if user or email already exists
    let check;
    try {
      check = await checkUser(req, username, email, `Seeker`);
    } catch (err) {
      throw({status:500, error: err, reason: 'check failed'});
    }
    if(check.exists != false) {
      throw({status: 400, error: 'failed seeker add', reason: check.reason});
    }
    // encrypt password, add user to database, respond to caller, and log successful registration
    await bcrypt.hash(pass, 10)
    .then(async hash => {
      try {
        const [user] = await req.db.query(`
          INSERT INTO Seeker (seeker_id, user_name, user_pass, email)
          VALUES (uuid_to_bin(uuid()), :username, :pass, :email);
        `, {
          username: username,
          pass: hash,
          email: email
        });
        res.status(201).json({success: true});
        console.log('USER', user);
        writer.write(`${setTimestamp(newTime)} | status: 201 | source: /register/seeker | success: job seeker ${username} added | ${username}@${req.socket.remoteAddress}\n`);
      } catch (err) {
        res.status(500).json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/seeker bcrypt\.then | error: ${err} | attempt: ${username}@${req.socket.remoteAddress}\n`);
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
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | registration attempt: employer\n`);
  const {
    username,
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
      username == null ||
      pass == null ||
      email == null ||
      mobile == null ||
      company == null ||
      website == null ||
      industry == null
    ) {
      throw({status: 400, error: 'failed employer add', reason: 'missing field'});
    }
    if(
      !validSAN(username) ||
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
      check = await checkUser(req, username, email, `Employer`, company);
    } catch (err) {
      throw({status:500, error: err, reason: 'check failed'});
    }
    if(check.exists != false) {
      throw({status: 400, error: 'failed employer add', reason: check.reason});
    }
    // console.log("shouldn't see this");
    await bcrypt.hash(pass, 10)
    .then(async hash => {
      try {
        const [user] = await req.db.query(`
          INSERT INTO Employer (employer_id, user_name, user_pass, email, mobile, company, website, industry)
          VALUES (uuid_to_bin(uuid()), :username, :pass, :email, :mobile, :company, :website, industry);
        `, {
          username: username,
          pass: hash,
          email: email,
          mobile: mobile,
          company: company,
          website: website,
          industry: industry
        });
        res.status(201).json({success: true, user: user});
        console.log('USER', user);
        writer.write(`${setTimestamp(newTime)} | status: 201 | source: /register/employer | success: employer ${username} @ ${company} added | @${req.socket.remoteAddress}\n`);
      } catch (err) {
        res.status(500).json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/employer bcrypt\.then | error: ${err} | attempt: ${username}@${req.socket.remoteAddress}\n`);
      }});
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /register/employer | error: ${err} | attempt: ${username}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /register/employer | error: ${err.error} | reason: ${err.reason} | attempt: ${username}@${req.socket.remoteAddress}\n\n`);
    }
  }
});

app.post('/login/seeker', async (req, res) => {
  console.log('login attempt: seeker');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | login attempt: seeker\n`);
  const {cred, pass} = req.body;
  try {
    let check;
    if(cred == null || pass == null) {
      throw({status: 400, error: 'failed seeker login', reason: 'missing field'});
    }
    if(
      !validSAN(cred) ||
      !validSAN(pass)
    ) {
      throw({status: 400, error: 'failed seeker login', reason: 'invalid input'});
    }
    check = await checkUser(req, cred, cred, `Seeker`);
    if(check.exists == false) {
      throw({status: 400, error: 'failed seeker login', reason: 'user not found'});
    }
    let response;
    if(!cred.includes('@')) {
      response = await req.db.query(`SELECT user_name, user_pass, email, hex(seeker_id) AS user_id FROM Seeker
        WHERE (user_name = :cred AND delete_flag = 0);`,
        {cred: cred}
      );
    } else {
      response = await req.db.query(`SELECT user_name, user_pass, email, hex(seeker_id) AS user_id FROM Seeker
        WHERE email = :cred AND delete_flag = 0;`,
        {cred: cred}
      );
    }
    const [[users]] = response;
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
      user_name: users.user_name,
      email: users.email,
      exp: timeNow + (60 * 60 * 24 * 7 * 2)
    }
    
    const encodedUser = jwt.sign(payload, process.env.JWT_KEY);
    
    res.status(200).json({success: true, user_name: users.user_name, email: users.email, jwt: encodedUser});
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /login/seeker | login: seeker ${users.user_name} logged in | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /login/seeker | error: ${err} | attempt: ${username}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /login/seeker | error: ${err.error} | reason: ${err.reason} | attempt: ${username}@${req.socket.remoteAddress}\n`);
    }
  }
});

app.post('/login/employer', async (req, res) => {
  console.log('login attempt: employer');
  const timeNow = Math.ceil(Date.now() / 1000);
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | login attempt: employer\n`);
  const {cred, pass, company} = req.body;
  try {
    let check;
    if(cred == null || pass == null || company == null) {
      console.log('bib')
      throw({status: 400, error: 'failed employer login', reason: 'missing field'});
    }
    if(
      !validSAN(cred) ||
      !validSAN(pass)
    ) {
      console.log('bub')
      throw({status: 400, error: 'failed employer login', reason: 'invalid input'});
    }
    check = await checkUser(req, cred, cred, `Employer`, company);
    if(check.exists == false) {
      console.log('bob')
      throw({status: 400, error: 'failed employer login', reason: 'user not found'});
    }
    let response;
    if(!cred.includes('@')) {
      response = await req.db.query(`SELECT user_name, user_pass, email, hex(employer_id) AS user_id FROM Employer
        WHERE (user_name = :cred AND delete_flag = 0 AND company = :company);`,
        {
          cred: cred,
          company: company
        }
      );
    } else {
      response = await req.db.query(`SELECT user_name, user_pass, email, hex(employer_id) AS user_id FROM Employer
        WHERE (email = :cred AND delete_flag = 0 AND company = :company);`,
        {
          cred: cred,
          company: company
        }
      );
    }
    const [[users]] = response;
    if (!users) {
      console.log('beb')
      throw({status: 500, error: 'failed login', reason: 'user does not exist'});
    }
    const dbPassword = `${users.user_pass}`;
    const compare = await bcrypt.compare(pass, dbPassword);
    if(!compare) {
      console.log('bab')
      throw({status: 400, error: 'failed login',reason: 'incorrect password'});
    }
    const payload = {
      user_id: users.user_id,
      user_name: users.user_name,
      email: users.email,
      company: company,
      exp: timeNow + (60 * 60 * 24 * 7 * 2)
    }
    
    const encodedUser = jwt.sign(payload, process.env.JWT_KEY);
    
    res.status(200).json({success: true, user_name: users.user_name, email: users.email, company: company, jwt: encodedUser});
    writer.write(`${setTimestamp(newTime)} | status: 200 | source: /login/employer | success: ${users.user_name} @ ${company} logged in | @${req.socket.remoteAddress}\n`);
  } catch (err) {
    console.warn(err);
    if(!err.reason) {
      res.status(500).json({success: false, error: 'server failure'});
      writer.write(`${setTimestamp(newTime)} | status: 500 | source: /login/employer | error: ${err} | attempt: ${username}@${req.socket.remoteAddress}\n`);
    }
    else {
      res.status(!err.status ? 500 : err.status).json({success: false, error: err.reason});
      writer.write(`${setTimestamp(newTime)} | status: ${!err.status ? 500 : err.status} | source: /login/employer | error: ${err.error} | reason: ${err.reason} | attempt: ${username}@${req.socket.remoteAddress}\n`);
    }
  }
});

// Check if user already exists for that type of user
async function checkUser(req, user, email, table, company) {
  const newTime = new Date(Date.now());
  try {
    let sql;
    if(table == 'Seeker'){
      sql = ' SELECT CASE WHEN EXISTS(SELECT 1 FROM ' +
        table +
        ' WHERE user_name = "' +
        user +
        '") THEN (select delete_flag from ' +
        table +
        ' WHERE user_name = "' +
        user +
        '" AND delete_flag = 0) WHEN EXISTS(SELECT 1 FROM ' +
        table +
        ' WHERE email = "' +
        email +
        '") THEN 1 ELSE null END AS checked FROM ' +
        table +
        ' LIMIT 1;';
    ;} else if (table == 'Employer'){
      sql = ' SELECT CASE WHEN EXISTS(SELECT 1 FROM ' +
        table +
        ' WHERE user_name = "' +
        user +
        '" AND company = "' +
        company +
        '") THEN (select delete_flag from ' +
        table +
        ' WHERE user_name = "' +
        user +
        '" AND delete_flag = 0) WHEN EXISTS(SELECT 1 FROM ' +
        table +
        ' WHERE email = "' +
        email +
        '" AND company = "' +
        company +
        '") THEN 1 ELSE null END AS checked FROM ' +
        table +
        ' LIMIT 1;';
    } else {
      throw('Not a valid check');
    }
    const [[check]] = await req.db.query(sql);
    switch (check.checked) {// query return logic
      case 0:
        return {exists: true, reason: 'username taken'};
      case 1:
        return {exists: true, reason: 'email already registered'};
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

function logger(writeOut, newTime, address, source, user) {
  writer.write(`${setTimestamp(newTime)} | status: ${writeOut.status != null ? writeOut.status : 500} | source: ${source} | error: ${writeOut.error} | reason: ${writeOut.reason} | user: ${user}@${address}\n`);
}

function errLogger(errOut, newTime, address, source, user) {
  writer.write(`${setTimestamp(newTime)} | status: ${errOut.status != null ? errOut.status : 500} | source: ${source} | error: ${errOut.error} | reason: ${errOut.reason} | user: ${user}@${address}\n`);
}

// Human readable timestamp for log
function setTimestamp(timeUpdate) {
  console.log(timeUpdate)
  console.log(time)
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
