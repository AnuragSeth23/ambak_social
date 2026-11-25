const mysql = require("mysql2/promise");
 
// Connection details come from the .env file (not written in code)
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
 
module.exports = db;
 






