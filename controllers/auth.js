const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator/check')

const User = require('../models/user');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const user = require('../models/user');

const transporter = nodemailer.createTransport(sendgridTransport({
  auth: {
    api_key: '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'
  }
}));

exports.getLogin = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email:'',
      password:''
    },
    validationErrors:[]
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
      email: '',
      password:'',
      confirmPassword:''
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput:{
        email: email,
        password: password
      },
      validationErrors: errors.array()
    });
  }
  User.findOne( {email: email} )
    .then(user => {
      if (!user) {
        res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid Email or Password.',
          oldInput:{
            email: email,
            password: password
          },
          validationErrors: []
        });
      }
      
      bcrypt
      .compare(password, user.password)
      .then(doMatch => {
        if (doMatch) {
          req.session.isLoggedIn = true;
          req.session.user = user;

            return req.session.save(err => {
              console.log(err);
              res.redirect('/')
            });
        }
        res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login',
          errorMessage: 'Invalid Email or Password.',
          oldInput:{
            email: email,
            password: password
          },
          validationErrors: []
        });
    })
      .catch(err => {
        console.log(err);
        res.redirect('/login');
      });
      
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      next(error);
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: confirmPassword
      },
      validationErrors: errors.array()
    });
  }

  
    bcrypt
    .hash(password, 12)
    .then( (hashedPassword) => {

      const user = new User( {
        email: email,
        password: hashedPassword,
        cart: { items: [] }
      } )

      return user.save();
    } )

    .then(result => {
      result => res.redirect('/login')
      return transporter.sendMail({
        to:email,
        from:'akartik.2910@gmail.com',
        subject:'Sign-up Successful',
        html:'<h1>Welcome!.<br>You are a Member of our website now.<br>Thank You for successfully registering at our website.</h1>'
      });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      next(error);
    });

};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error')
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({email: req.body.email})
    .then(user => {
      if (!user) {
        req.flash('error','NO account with that E-mail found.');
        return res.redirect('/reset');
      }
      user.resetToken = token;
      user.resetTokenExpiration = Date.now()+3600000;
      return user.save();
    })
    .then(result => {
      res.redirect('/');
      transporter.sendMail({
        to:req.body.email,
        from:'akartik.2910@gmail.com',
        subject:'Password Reset',
        html: `
            <p>You requested a Password change</p>
            <p> Click this <a href="http://localhost:3000/reset/${token}">Link</a> to set a new password</p>
          `
        });      
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      next(error);
    });
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({resetToken: token, resetTokenExpiration: {$gt: Date.now()} })
  .then(user => {
    let message = req.flash('error')
    if (message.length > 0) {
      message = message[0];
    } 
    else {
      message = null;
    }
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'New Password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token
      });
  })
  .catch(err => {
    const error = new Error(err);
    error.httpStatusCode = 500;
    next(error);
  });
  
  
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    resetTokenExpiration: {$gt: Date.now()},
    _id: userId
  })
  .then(user =>{
    resetUser = user;
    return bcrypt.hash(newPassword, 12);
  })
  .then(hashedPassword => {
    resetUser.password = hashedPassword;
    resetUser.resetToken = undefined;
    resetUser.resetTokenExpiration = undefined;
    resetUser.save();
    return res.redirect('/login')
  })
  .catch(err => {
    const error = new Error(err);
    error.httpStatusCode = 500;
    next(error);
  });
};
