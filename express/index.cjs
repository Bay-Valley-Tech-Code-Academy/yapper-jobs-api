const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
require('dotenv').config();

// const uts = Date.now()
const time = new Date(Date.now());
const writer = fs.createWriteStream('express/ape.log', {flags: 'a'});

const app = express();
const port = process.env.PORT; // default port

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

app.use(bodyParser.json());

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
  console.log('Registration attempt: seeker');
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | Registration attempt: seeker\n`);
  const {
    username,
    pass,
    email
  } = req.body;
  try {
    let check;
    if(username == null || pass == null || email == null) {
      throw({errStatus: 400, errObj: {error: 'failed seeker add', reason: 'missing field'}});
    } 
    try {
      check = await checkUser(req, username, `Seeker`);
    } catch (err) {
      throw({errStatus:500, errObj: {error: err, reason: 'check failed'}});
    }
    if(check != false) {
      throw({errStatus: 400, errObj: {error: 'failed seeker add', reason: check.reason}});
    }
    // console.log("shouldn't see this");
    await bcrypt.hash(pass, 10)
    .then(async hash => {
      try {
        const [user] = await req.db.query(`
          INSERT INTO Seeker (seeker_id, user_name, user_pass, email)
          VALUES (uuid_to_bin(uuid()), :username, :pass, :email)
        `, {
          username: username,
          pass: hash,
          email: email
        });
        res.status(201);
        res.json({success: true});
        console.log('USER', user);
      } catch (err) {
        console.log('error', err);
      }});
  } catch (err) {
    res.status(err.errStatus != null ? err.errStatus : 500);
    res.json({success: false, error: err.errObj.reason})
    console.warn(err);
    writer.write(`${setTimestamp(newTime)} | error: ${err.errObj.error} | reason: ${err.errObj.reason} | @${req.socket.remoteAddress}\n`);
  }
});

// Register endpoint for employer
app.post('/register/employer', async (req, res) => {
  console.log('Registration attempt: employer');
  const newTime = new Date(Date.now());
  writer.write(`${setTimestamp(newTime)} | Registration attempt: employer\n`);
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
      // res.status(400);
      // res.json({Error: 'missing field'});
      throw({errStatus: 400, errObj: {error: 'failed employer add', reason: 'missing field'}});
    } 
    try {
      check = await checkUser(req, username, email, `Employer`, company);
    } catch (err) {
      throw({errStatus:500, errObj: {error: err, reason: 'check failed'}});
    }
    if(check.exists != false) {
      throw({errStatus: 400, errObj: {error: 'failed employer add', reason: check.reason}});
    }
    // console.log("shouldn't see this");
    await bcrypt.hash(pass, 10)
    .then(async hash => {
      try {
        const [user] = await req.db.query(`
          INSERT INTO Employer (employer_id, user_name, user_pass, email, mobile, company, website, industry)
          VALUES (uuid_to_bin(uuid()), :username, :pass, :email, :mobile, :company, :website, industry)
        `, {
          username: username,
          pass: hash,
          email: email,
          mobile: mobile,
          company: company,
          website: website,
          industry: industry
        });
        res.status(201);
        res.json({success: true});
        console.log('USER', user);
      } catch (err) {
        res.status(500);
        res.json({success: false, error: 'server failure'})
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | error: ${err}\n`);
      }});
  } catch (err) {
    res.status(err.errStatus != null ? err.errStatus : 500);
    res.json({success: false, error: err.errObj.reason != null ? err.errObj.reason : 'server failure'})
    console.warn(err);
    writer.write(`${setTimestamp(newTime)} | error: ${err.errObj.error} | reason: ${err.errObj.reason} | @${req.socket.remoteAddress}\n`);
  }
});

// Check if user already exists for that type of user
async function checkUser(req, user, email, table, company) {
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
        ' WHERE email "' +
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
        ' WHERE email "' +
        email +
        '" AND company = "' +
        company +
        '") THEN 1 ELSE null END AS checked FROM ' +
        table +
        ' LIMIT 1;';
    } else {
      throw('Not a valid check');
    }
    const check = await req.db.query(sql);
    console.log(check)
    switch (check[0][0].checked) {// query return logic
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

/* OR (email = "' +
        email +
        '" AND company = "' +
        company + */

function setTimestamp(timeUpdate) {
  console.log(timeUpdate)
  console.log(time)
  const months = (timeUpdate.getMonth() < 10) ? '0' + timeUpdate.getMonth() : timeUpdate.getMonth();
  const days = (timeUpdate.getDate() < 10) ? '0' + timeUpdate.getDate() : timeUpdate.getDate();
  const hours = (timeUpdate.getHours() < 10) ? '0' + timeUpdate.getHours() : timeUpdate.getHours();
  const minutes = (timeUpdate.getMinutes() < 10) ? '0' + timeUpdate.getMinutes() : timeUpdate.getMinutes();
  const seconds = (timeUpdate.getSeconds() < 10) ? '0' + timeUpdate.getSeconds() : timeUpdate.getSeconds();
  const formatted = timeUpdate.getFullYear() + ' ' + months + ' ' + days + ' ' + hours + ':' + minutes + ':' + seconds;
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
  writer.write(`${setTimestamp(time)} | status: server started\n`)
});
