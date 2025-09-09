const express = require('express');
const router = express.Router();

router.use('/upload', require('./upload'));
router.use('/admin', require('./admin'));

module.exports = router;
