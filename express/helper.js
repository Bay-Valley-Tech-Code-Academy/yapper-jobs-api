const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const writer = fs.createWriteStream('./ape.log', {flags: 'a'});// open log for appending, creates file if it does not exist
// Two letter abbreviation for states, Puerto Rico, and D.C.
const TLAbbr = ["AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "PR", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"]

let it = 0;

// for testing
function bob(msg) {
  if(!msg) {
    console.log(it);
    it++;
  } else if (msg === 'reset') {
    console.log('resetting count');
    it = 0;
  } else {
    console.log(msg);
  }
}

function setTimestamp (timeUpdate) {
  const months = (timeUpdate.getMonth() < 10) ? '0' + timeUpdate.getMonth() : timeUpdate.getMonth();
  const days = (timeUpdate.getDate() < 10) ? '0' + timeUpdate.getDate() : timeUpdate.getDate();
  const hours = (timeUpdate.getHours() < 10) ? '0' + timeUpdate.getHours() : timeUpdate.getHours();
  const minutes = (timeUpdate.getMinutes() < 10) ? '0' + timeUpdate.getMinutes() : timeUpdate.getMinutes();
  const seconds = (timeUpdate.getSeconds() < 10) ? '0' + timeUpdate.getSeconds() : timeUpdate.getSeconds();
  const formatted = timeUpdate.getFullYear() + '-' + months + '-' + days + ' ' + hours + ':' + minutes + ':' + seconds;
  return formatted;
}

// parse integer
function iPar(str) {
  return Number.parseInt(str, 10);
}

function validSAN (check, len) {
  if(typeof(check) === 'string') {
    if(check.length < 3 || check.length > len) return false;
    const pattern = /^[A-Za-z 0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
    const checked = pattern.test(check);
    return checked;
  }
  return false;
}

function validJSON (check) {
  const newTime = new Date(Date.now());
  if(check === undefined || check === null) return true;
  if(typeof(check) !== 'object') return false;
  try{
    const arr = Object.values(check);
    const valid = arr.every((entry) => {
      if(typeof(entry) !== 'string' && typeof(entry) !== 'object' && typeof(entry) !== 'boolean' && typeof(entry) !== 'number') return false;
      if(typeof(entry) === 'object') {
        const valid2 = validJSON(entry);
        if(!valid2) return false;
      }
      return true;
    });
    return valid;
  } catch (err) {
    console.warn(err);
    writer.write(`${setTimestamp(newTime)} | | source: helper validJSON | error: ${err.message} | | server\n`);
    return false;
  }
}

module.exports = {
// Check if user already exists for that type of user
  checkUser: async function (req, email) {
    const newTime = new Date(Date.now());
    try {
      const [[check]] = await req.db.query(`
      SELECT CASE 
        WHEN EXISTS(SELECT 1 FROM Employer WHERE (email = :email AND delete_flag = 0))
          THEN (SELECT delete_flag FROM Employer WHERE (email = :email AND delete_flag = 0))
        WHEN EXISTS(SELECT 1 FROM Seeker WHERE (email = :email AND delete_flag = 0))
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
        case null:
          return {exists: false, reason: 'user not found'};
        default:
          throw({message: 'unexpected value returned while searching'});
      }
    } catch(err) {
        console.warn(err);
        writer.write(`${setTimestamp(newTime)} | | source: helper.checkUser | error: ${err.message} | | server\n`);
        return err;
    }
  },

  checkAuth: async function (req, user_id, company, job_id) {
    const newTime = new Date(Date.now());
    try {
      if(!job_id) {
        const [[check]] = await req.db.query(`
        SELECT approve_flag, company FROM Employer
          WHERE employer_id = UNHEX(:id);
        `, {
          id: user_id
        });
        if(!check || !check.approve_flag || company !== check.company) {
          return false;
        } else {
          return true;
        }
      } else {
        const [[check]] = await req.db.query(`
          SELECT approve_flag, company FROM Employer
          WHERE employer_id = UNHEX(:id);
        `, {
          id: user_id
        });
        const [[check2]] = await req.db.query(`
          SELECT company FROM Job
          WHERE job_id = UNHEX(:id);
        `, {
          id: job_id
        });
        if(!check || !check2 || !check.approve_flag || company !== check.company || company !== check2.company) {
          return false;
        } else {
          return true;
        }
      }
    } catch (err) {
      console.log(err.message);
      writer.write(`${setTimestamp(newTime)} | | source: helper.checkAuth | error: ${err.message} | | server\n`);
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
        id: users.user_id,
        firstName: users.first_name,
        lastName: users.last_name,
        email: users.email,
        company: !users.company ? null : users.company,
        jwt: encodedUser
      }
    } catch(err) {
      if(!err.reason) {
        return {status: 500, error: err.message, reason: null};
      }
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

  newTime: function () {
    return new Date(Date.now());// for logging
  },

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
  validA: function (check, len) {
    bob()
    if(typeof(check) === 'string') {
      if(check.length < 3 || check.length > len) return false;
      const pattern = /^[A-Za-z ]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },

  // numeric
  validN: function (check) {
    bob()
    if(typeof(check) === 'number') {
      if(check < 1000000 && check > 0) {
        return true;
      }
    }
    return false;
  },

  // alphanumeric
  validAN: function (check, len) {
    bob()
    if(typeof(check) === 'string') {
      if(check.length < 3 || check.length > len) return false;
      const pattern = /^[A-Za-z 0-9]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },
  
  // special characters + alphanumeric
  validSA: function (check, len) {
    bob()
    if(typeof(check) === 'string') {
      if(check.length < 3 || check.length > len) return false;
      const pattern = /^[A-Za-z \!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },

  // special characters + alphanumeric
  validSAN: function (check, len) {
    bob()
    if(typeof(check) === 'string') {
      if(check.length < 1 || check.length > len) return false;
      const pattern = /^[A-Za-z 0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
      const checked = pattern.test(check);
      return checked;
    }
    return false;
  },

  // state
  validState: function (check) {
    bob()
    if(typeof(check) === 'string') {
      if(check.length === 2) {
        const arr = TLAbbr.filter((state) => state === check);
        return arr[0] ? true : false;
      }
    }
    return false;
  },

  // json
  validJSON: function (check) {
    bob()
    const newTime = new Date(Date.now());
    if(check === null || check === undefined) return true;
    if(typeof(check) !== 'object' && typeof(check) !== 'array') {
      console.log(typeof(check))
      return false;
    }
    try{
      const arr = Object.values(check);
      const valid = arr.every((entry) => {
        if(typeof(entry) !== 'string' && typeof(entry) !== 'object' && typeof(entry) !== 'boolean' && typeof(entry) !== 'number') return false;
        if(typeof(entry) === 'object') {
          const valid2 = validJSON(entry);
          if(!valid2) return false;
        }
        return true;
      });
      return valid;
    } catch (err) {
      console.warn(err);
      writer.write(`${setTimestamp(newTime)} | | source: helper.validJSON | error: ${err} | | server\n`);
      return false;
    }
  },

  // date const pattern = /^[A-Za-z0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/
  validDate: function (check) {
    bob()
    const newTime = new Date(Date.now());
    const pattern = /^[1-2][0-9][0-9][0-9]-[0-1][0-9]+$/;
    if(!pattern.test(check)) return false;
    try{
      const arr = check.split('-');
      const year = iPar(arr[0]);
      if(year > newTime.getFullYear() || year < 1950) return false;
      const checkDate = new Date(check);
      const newCheck = checkDate.getTime();
      const newMax = newTime.getTime();
      return newCheck < newMax ? true : false;
    } catch (err) {
      console.warn(err);
      writer.write(`${setTimestamp(newTime)} | | source: helper.validDate | error: ${err} | | server\n`);
      return false;
    }
  },

  // non-paradoxical dates
  validDates: function (check, check2) {
    bob()
    const newTime = new Date(Date.now());
    try{
      const arr = check.split('-');
      const year = iPar(arr[0]);
      const month = iPar(arr[1]);
      let day;
      if(arr[2] !== undefined) {
        day = iPar(arr[2]);
      }
      const arr2 = check2.split('-');
      const year2 = iPar(arr2[0]);
      const month2 = iPar(arr2[1]);
      let day2;
      if(arr2[2] !== undefined) {
        day2 = iPar(arr2[2]);
      }
      if(year <= year2) {
        if(month <= month2 || year < year2) {
          if(arr[2] && arr2[2] && year === year2 && month === month2) {
            if(day > day2) return false;
          }
          return true;
        }
      }
      return false;
    } catch (err) {
      console.warn(err);
      writer.write(`${setTimestamp(newTime)} | | source: helper.validDates | error: ${err} | | internal\n`);
      return false;
    }
  },

  // expiration date
  validExpDate: function (check) {
    bob()
    const newTime = new Date(Date.now());
    const pattern = /^2[0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]+$/;
    if(check === null) return {valid: true};
    if(!pattern.test(check)) return {valid: false};
    try{
      const arr = check.split('-');
      const year = Number.parseInt(arr[0], 10);
      if(year < newTime.getFullYear() || year > 3000) return {valid: false};
      const expDate = new Date(check);
      const newExp = (expDate.getTime() / (24 * 60 * 60 * 1000));
      const expUnix = ((newExp * 24 * 60) + expDate.getTimezoneOffset()) * 60 * 1000;
      const newMin = Math.floor((newTime.getTime() / (24 * 60 * 60 * 1000)) + 15);
      const minUnix = ((newMin * 24 * 60) + newTime.getTimezoneOffset()) * 60 * 1000;
      return {
        valid: expUnix >= minUnix ? true : false,
        expDate: new Date(expUnix),
      };
    } catch (err) {
      console.warn(err);
      writer.write(`${setTimestamp(newTime)} | | source: helper.validExpDate | error: ${err} | | server\n`);
      return {valid: false};
    }
  },

  // multer filter
  fileFilter: function (req, file, cb) {
    if(file.mimetype === 'image/gif' || file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
      cb(null, true);
    } else {
      
    }
  },

  // create hash to use as filename
  filename: function (req, file, cb) {
    const hash = crypto.createHash('aes-256-cfb')
  }
}
