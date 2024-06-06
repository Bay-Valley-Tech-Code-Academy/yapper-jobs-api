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

// Export the transporter and sendPasswordResetEmail function
module.exports = { sendEmail };