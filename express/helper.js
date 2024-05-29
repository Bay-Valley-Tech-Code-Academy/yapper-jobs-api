const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const bcrypt = require('bcrypt');

const writer = fs.createWriteStream('./ape.log', {flags: 'a'});// open log for appending, creates file if it does not exist
// Two letter abbreviation for states, Puerto Rico, and D.C.
const TLAbbr = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "PR", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"]


function setTimestamp (timeUpdate) {
  const months = (timeUpdate.getMonth() < 10) ? '0' + timeUpdate.getMonth() : timeUpdate.getMonth();
  const days = (timeUpdate.getDate() < 10) ? '0' + timeUpdate.getDate() : timeUpdate.getDate();
  const hours = (timeUpdate.getHours() < 10) ? '0' + timeUpdate.getHours() : timeUpdate.getHours();
  const minutes = (timeUpdate.getMinutes() < 10) ? '0' + timeUpdate.getMinutes() : timeUpdate.getMinutes();
  const seconds = (timeUpdate.getSeconds() < 10) ? '0' + timeUpdate.getSeconds() : timeUpdate.getSeconds();
  const formatted = timeUpdate.getFullYear() + '-' + months + '-' + days + ' ' + hours + ':' + minutes + ':' + seconds;
  return formatted;
}

function validSAN (check) {
  if(typeof(check) === 'string') {
    const pattern = /^[A-Za-z0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
    const checked = pattern.test(check);
    return checked;
  }
  return false;
}

module.exports = {
// Check if user already exists for that type of user
  checkUser: async function (req, email) {
    const newTime = new Date(Date.now());
    try {
      const [[check]] = await req.db.query(`
      SELECT CASE 
        WHEN EXISTS(SELECT 1 FROM Employer WHERE email = :email)
          THEN (SELECT delete_flag FROM Employer WHERE (email = :email AND delete_flag = 0))
        WHEN EXISTS(SELECT 1 FROM Seeker WHERE email = :email)
          THEN (SELECT delete_flag FROM Seeker WHERE (email = :email AND delete_flag = 0))
        ELSE NULL
      END AS checked,
      CASE 
        WHEN EXISTS(SELECT 1 FROM Employer WHERE (email = :email AND delete_flag = 0))
          THEN (SELECT "employer" AS usertype)
        WHEN EXISTS(SELECT 1 FROM Seeker WHERE (email = :email AND delete_flag = 0))
          THEN (SELECT "seeker" AS usertype)
        ELSE NULL
      END AS usertype,
      CASE 
        WHEN EXISTS(SELECT 1 FROM Employer WHERE (email = :email AND delete_flag = 0))
          THEN (SELECT HEX(employer_id) FROM Employer WHERE (email = :email AND delete_flag = 0))
        WHEN EXISTS(SELECT 1 FROM Seeker WHERE (email = :email AND delete_flag = 0))
          THEN (SELECT HEX(seeker_id) FROM Seeker WHERE (email = :email AND delete_flag = 0))
        ELSE NULL
      END AS user_id;
      `,{
        email: email
      });

      switch (check.checked) {// query return logic
        case 0:
          return {exists: true, reason: 'email already registered', usertype: check.usertype, userId: check.user_id};
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
  },

  checkAuth: async function (req, user_id, company) {
    const newTime = new Date(Date.now());
    try {
      const [[check]] = await req.db.query(`
      SELECT approve_flag, company FROM employer
        WHERE employer_id = UNHEX(:id);
      `, {
        id: user_id
      });
      if(!check || !check.approve_flag || company !== check.company) {
        return false;
      } else {
        return true;
      }
    } catch (err) {
      console.log(err.message);
      writer.write(`${setTimestamp(newTime)} | error: ${err}\n`);
      return err;
    }
  },

  login: async function (req, email, pass, table) {
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
        company: !users.company ? null : users.company,
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
    
  },

  /* function logger(writeOut, newTime, address, source, user) {
    writer.write(`${setTimestamp(newTime)} | status: ${writeOut.status != null ? writeOut.status : 500} | source: ${source} | error: ${writeOut.error} | reason: ${writeOut.reason} | user: ${user}@${address}\n`);
  }

  function errLogger(errOut, newTime, address, source, user) {
    writer.write(`${setTimestamp(newTime)} | status: ${errOut.status != null ? errOut.status : 500} | source: ${source} | error: ${errOut.error} | reason: ${errOut.reason} | user: ${user}@${address}\n`);
  }
 */
  // Human readable timestamp for log
  setTimestamp: function (timeUpdate) {
    const months = (timeUpdate.getMonth() < 10) ? '0' + timeUpdate.getMonth() : timeUpdate.getMonth();
    const days = (timeUpdate.getDate() < 10) ? '0' + timeUpdate.getDate() : timeUpdate.getDate();
    const hours = (timeUpdate.getHours() < 10) ? '0' + timeUpdate.getHours() : timeUpdate.getHours();
    const minutes = (timeUpdate.getMinutes() < 10) ? '0' + timeUpdate.getMinutes() : timeUpdate.getMinutes();
    const seconds = (timeUpdate.getSeconds() < 10) ? '0' + timeUpdate.getSeconds() : timeUpdate.getSeconds();
    const formatted = timeUpdate.getFullYear() + '-' + months + '-' + days + ' ' + hours + ':' + minutes + ':' + seconds;
    return formatted;
  },

  // validate input
  // alpha
  validA: function (check) {
    if(typeof(check) === 'string') {
      const pattern = /^[A-Za-z]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },
  // numeric
  validN: function (check) {
    if(typeof(check) === 'number') {
      if(check < 1000000) {
        return true;
      }
    }
    return false;
  },
  // alphanumeric
  validAN: function (check) {
    if(typeof(check) === 'string') {
      const pattern = /^[A-Za-z0-9]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },
  // special characters + alphanumeric
  validSAN: function (check) {
    if(typeof(check) === 'string') {
      const pattern = /^[A-Za-z0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },
  // state
  validState: function (check) {
    if(typeof(check) === 'string') {
      if(check.length === 2) {
        const arr = TLAbbr.filter((state) => state === check);
        return arr[0] ? true : false;
      }
    }
    return false;
  },
  // json we get should only be strings
  validJSON: function (check) {
    console.log(check)
    if(check === undefined || check === null) return true;
    try{
      const arr = Object.values(check);
      const valid = arr.entries((entry) => validSAN(entry));
      return valid;
    } catch (err) {
      console.warn(err);
    }
  },
}