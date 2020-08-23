const express = require('express');
const { check, body, header } = require('express-validator/check');
const User = require('../models/user');

const authController = require('../controllers/auth');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login',
        [
            check('email','Please enter a valid Email address').isEmail().normalizeEmail(),
            body('password','Please enter an alphanumeric password of atleast 5 charcaters')
            .isLength({min: 5})
            .isAlphanumeric()
            .trim()
        ], 
        authController.postLogin);

router.post(
    '/signup',
    [ 
    check('email')
        .isEmail()
        .withMessage('Please enter a valid Email')
        
        .custom((value,{ req }) => {
            return User.findOne({email: value}).then(userDoc => {
                    if (userDoc) {
                        return Promise.reject( 
                        'E-Mail exists already, please pick a different one.'
                        );
                    } 
                });                  
        })
        .normalizeEmail(),
    body('password','Please enter an Alphanumeric Password of atleast 5 characters') // lecture 291-292
    .isLength({min: 5})
    .isAlphanumeric().trim(),
    body('confirmPassword').trim().custom(( value, { req } ) => {
        if (value !== req.body.password)
            throw new Error('Passwords do not match!');
        return true;
    })
    ],
    authController.postSignup );

router.post('/logout', authController.postLogout);

router.get('/reset',authController.getReset);

router.post('/reset',authController.postReset);

router.get('/reset/:token',authController.getNewPassword);

router.post('/new-password',authController.postNewPassword);

module.exports = router;