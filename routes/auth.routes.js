const { Router } = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');

const config = require('config');
const User = require('../models/User');

const router = Router();

// /api/auth/sign-up
router.post(
    '/sign-up',
    [
      check('email', 'Wrong email address').isEmail(),
      check('password', 'Wrong password, at least 6 characters long')
      .isLength({ min: 6 })
    ],
    async (req, res) => {
      try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
          return res.status(400).json({
            errors: errors.array(),
            message: 'You entered incorrect data'
          })
        }

        const { email, password } = req.body;

        const candidate = await User.findOne({ email });

        if (candidate) {
          return res.status(400).json({ message: 'This account already exists' })
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ email, password: hashedPassword });

        await user.save();

        res.status(201).json({ message: 'You create an account' })
      } catch (e) {
        res.status(500).json({ message: 'Server error' });
      }
    }
);

// /api/auth/sign-in
router.post(
    '/sign-in',
    [
      check('email', 'Wrong email address').normalizeEmail().isEmail(),
      check('password', 'Wrong password, please try again').exists()
    ],
    async (req, res) => {
      try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
          return res.status(400).json({
            errors: errors.array(),
            message: 'You entered incorrect data'
          })
        }

        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
          return res.status(404).json({message: 'User not found'})
        }

        const isMachPassword = await bcrypt.compare(password, user.password);

        if (!isMachPassword) {
          return res.status(400).json({message: 'You entered wrong password, please try again'})
        }

        const token = jwt.sign(
          { userId: user.id },
          config.get('jwtSecret'),
          { expiresIn: '1h'}
        );

        res.json({ token, userId: user.id })

      } catch (e) {
        res.status(500).json({ message: 'Server error' });
      }
    }
);

module.exports = router;