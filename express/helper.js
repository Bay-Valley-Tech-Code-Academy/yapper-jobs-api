const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const bcrypt = require('bcrypt');

module.exports = {
// Check if user already exists for that type of user
  checkUser: async function (req, email) {
    const newTime = new Date(Date.now());
    try {
      const [[check]] = await req.db.query(`
      SELECT CASE 
        WHEN EXISTS(SELECT 1 FROM Seeker WHERE email = :email)
          THEN (SELECT delete_flag FROM Seeker WHERE email = :email AND delete_flag = 0)
        ELSE null
        END AS checked,
        "seeker" AS usertype,
        seeker_id as user_id
      FROM Seeker
      UNION ALL
      SELECT CASE 
        WHEN EXISTS(SELECT 1 FROM Employer WHERE email = :email)
          THEN (SELECT delete_flag FROM Employer WHERE email = :email AND delete_flag = 0)
        ELSE null
        END AS checked,
        "employer" AS usertype,
        employer_id as user_id
      FROM Employer LIMIT 1;`,
      {email: email}
      );

      /* if(table == 'seeker'){
        const [[sql]] = await req.db.query(`
          SELECT CASE 
            WHEN EXISTS(SELECT 1 FROM Seeker WHERE email = :email)
              THEN (SELECT delete_flag FROM Seeker WHERE email = :email AND delete_flag = 0)
            ELSE null
            END AS checked
          FROM Seeker LIMIT 1;`,
          {email: email}
        );
        // check = sql;
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
        // check = sql;
      } else {
        throw('Not a valid check');
      } */
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
  // alphanumeric
  /* function validAN(check) {
    const pattern = /^[A-Za-z0-9]+$/g;
    const checked = pattern.test(check);
    return checked;
  } */
  // special characters + alphanumeric
  validSAN: function (check) {
    const pattern = /^[A-Za-z0-9\!\@\#\$\%\^\&\*\)\(+\=\._-]+$/g;
    const checked = pattern.test(check);
    return checked;
  }
}