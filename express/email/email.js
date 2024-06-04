const nodemailer = require("nodemailer");
require('dotenv').config();

const [seeker] = await req.db.query(`SELECT seeker_id FROM Seeker WHERE email = :email`, { email });
const [employer] = await req.db.query(`SELECT employer_id FROM Employer WHERE email = :email`, { email });

const transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: "notifications@yapper.email",
    pass: "jn7jnAPss4f63QBp6D",
  },
});

// async..await is not allowed in global scope, must use a wrapper
async function email() {
  // send mail with defined transport object
  const info = await transporter.sendMail({
    from: '"Yapper Jobs" <no-reply@yapper.email>', // sender address
    to: "bar@example.com, baz@example.com", // list of receivers
    subject: "Reset your password", // Subject line
    text: "Seems like you forgot your password. Click on the link to reset your password: http://localhost:5173/reset-password/${}/$", // plain text body
    html: "<b>Hello world?</b>", // html body
  });

  console.log("Message sent: %s", info.messageId);
  // Message sent: <d786aa62-4e0a-070a-47ed-0b0666549519@ethereal.email>
  console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
}
  
email().catch(console.error);

  // Generate SMTP service account from ethereal.email
/* nodemailer.createTestAccount((err, account) => {
    if (err) {
        console.error('Failed to create a testing account. ' + err.message);
        return process.exit(1);
    }

    console.log('Credentials obtained, sending message...');

    // Create a SMTP transporter object
    let transporter = nodemailer.createTransport({
        host: account.smtp.host,
        port: account.smtp.port,
        secure: account.smtp.secure,
        auth: {
            user: account.user,
            pass: account.pass
        }
    });

    // Message object
    let message = {
        from: 'Sender Name <sender@example.com>',
        to: 'Recipient <recipient@example.com>',
        subject: 'Nodemailer is unicode friendly ✔',
        text: 'Hello to myself!',
        html: '<p><b>Hello</b> to myself!</p>'
    };

    transporter.sendMail(message, (err, info) => {
        if (err) {
            console.log('Error occurred. ' + err.message);
            return process.exit(1);
        }

        console.log('Message sent: %s', info.messageId);
        // Preview only available when sending through an Ethereal account
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
    });
}); */