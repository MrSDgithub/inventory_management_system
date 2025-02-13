// userModel.js

const pool = require("../database/connection");
const bcrypt = require('bcryptjs');
const { generateAccessAndRefreshToken, refreshToken } = require('../utils/token'); 


// const bcrypt = require("bcrypt");
// const pool = require("../database"); // Ensure you have the correct database connection

exports.register = async (email, password, isAdmin, fname, lname) => {
  try {
    // Check if the user already exists
    const [existingUser] = await pool
      .promise()
      .query("SELECT * FROM users WHERE email = ?", [email]);

    if (existingUser.length > 0) {
      throw new Error("User already exists");
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
    const [result] = await pool
      .promise()
      .query(
        "INSERT INTO users (email, password, isAdmin, fname, lname) VALUES (?, ?, ?, ?, ?)",
        [email, hashedPassword, isAdmin, fname, lname]
      );

    return result;
  } catch (error) {
    throw error; // Re-throw the error to be handled by the caller
  }
};



exports.login = (email, password) => {
    return new Promise((resolve, reject) => {
        pool.query(
            "SELECT userId, password, isAdmin FROM users WHERE email = ?;",
            [email],
            (err, result) => {
                if (err) {
                    reject(err);
                } else {
                    if (result.length === 0) {
                        // No user found with the provided email
                        reject(new Error("Invalid email or password"));
                    } else {
                        const storedHashedPassword = result[0].password;
                        // Compare the provided password with the stored hashed password
                        bcrypt.compare(password, storedHashedPassword, (compareErr, isMatch) => {
                            if (compareErr) {
                                reject(compareErr);
                            } else if (!isMatch) {
                                // Passwords do not match
                                reject(new Error("Invalid email or password"));
                            } else {
                                // Passwords match, authenticate the user
                                let userData = {
                                    userId: result[0].userId,
                                    isAdmin: result[0].isAdmin,
                                }
                                const {token, refreshToken} = generateAccessAndRefreshToken(userData);
                                userData.token = token;
                                // if refresh token gives cros error avoid passing refresh token in cookies & pass as nrml param
                                userData.refreshToken = refreshToken;

                                // res.cookie('jwt', refreshToken, {
                                //     httpOnly: true,
                                //     sameSite: 'None', secure: true,
                                //     maxAge: 24 * 60 * 60 * 1000
                                // });

                                let response = [userData]
                                resolve(response);
                            }
                        });
                    }
                }
            }
        );
    });
};


