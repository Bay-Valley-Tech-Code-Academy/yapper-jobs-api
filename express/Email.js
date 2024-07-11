const nodemailer = require("nodemailer");
require('dotenv').config();

// Create the transporter object
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

// Function to send the password reset email
const sendEmail = (email, token) => {
  const resetLink = `http://localhost:5173/reset-password?token=${token}`; // Ensure `token` is correctly passed as an argument

  const mailOptions = {
    from: '"Yapper Jobs" <yapper-no-reply@gmail.com>',
    to: email,
    subject: 'Password Reset',
    html: `
    <div>
      <h1>Yapper Jobs</h1>
      <p>You requested a password reset. Click <a href="${resetLink}">here</a> to reset your password.</p>
    </div>
    `,
  };

  return transporter.sendMail(mailOptions)
    .then(info => {
      console.log('Email sent: ' + info.response);
      return info;
    })
    .catch(error => {
      console.error('Error sending email: ' + error.message);
      throw error;
    });
};

// Function to send employer an email when someone applies
const sendApplication = (email, job, seeker) => {

  const mailOptions = {
    from: '"Yapper Jobs" <yapper-no-reply@gmail.com>',
    to: email,
    subject: 'New Application',
    html: `
    <div>
      <h1>Yapper Jobs</h1>
      <p>${seeker.first_name} ${seeker.last_name} applied to ${job.title}</p>
    </div>
    `,
  };

  return transporter.sendMail(mailOptions)
    .then(info => {
      console.log('Email sent: ' + info.response);
      return info;
    })
    .catch(error => {
      console.warn('Error sending email: ' + error.message);
      throw error;
    });
};

// Function to send employer an email when someone applies
const sendDelete = (email, token) => {
  const deleteLink = `http://127.0.0.1:3000/delete?token=${token}`;

  const mailOptions = {
    from: '"Yapper Jobs" <yapper-no-reply@gmail.com>',
    to: email,
    subject: 'Deletion Requested',
    html: `
    <div>
      <h1>Yapper Jobs</h1>
      <p>Account deletion of Yapper Jobs profile ${email} was requested.</p>
      <p><a href="${deleteLink}">Click here</a> to confirm deletion.</p>
      <p>If you did not request this deletion, please reset your password and notify support.</p>
    </div>
    `,
  };

  return transporter.sendMail(mailOptions)
    .then(info => {
      console.log('Email sent: ' + info.response);
      return info;
    })
    .catch(error => {
      console.warn('Error sending email: ' + error.message);
      throw error;
    });
};

// Export the transporter and sendPasswordResetEmail function
module.exports = { sendEmail, sendApplication, sendDelete };