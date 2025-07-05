// Run this script with: node hash.js
const bcrypt = require('bcrypt');
const password = 'chrome'; // Change to your desired password
bcrypt.hash(password, 10, (err, hash) => {
  if (err) throw err;
  console.log('Hashed password:', hash);
});
