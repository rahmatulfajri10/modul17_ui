const express = require('express')
const db = require('../db.config/db.config')
const jwt = require('jsonwebtoken');
// const Auth = require('./auth')
const cookieParser = require('cookie-parser');
require("dotenv").config();
const bcrypt = require('bcrypt');
SECRET = process.env.SECRET


const register = async(req, res, next) => {
    
        // Get user input
        const { username, email, password} = req.body;
    
        // Validate user input
        if (!(email && password && username)) {
            return res.status(400).send("All input is required");
        }
    
        // check if user already exist
        // Validate if user exist in our database
        const data = await db.query(`SELECT * FROM unhan_modul_17 WHERE username = $1`, [username])
    
        if (!(data.rowCount == 0)) {
            return res.status(409).send("User Already Exist. Please Login");
        }
    
        //Encrypt user password
        // * 7. silahkan ubah password yang telah diterima menjadi dalam bentuk hashing
        const hashPassword = await bcrypt.hash(password, 10);

    
        // Create user in our database
        // 8. Silahkan coding agar pengguna bisa menyimpan semua data yang diinputkan ke dalam database
        db.query(`INSERT INTO unhan_modul_17 VALUES (DEFAULT, $1, $2, $3)`, [username, email.toLowerCase(), hashPassword],function (err, results){
            if (err) {
                return res.status(500).json({error: err});
            }
            else {
                // return new user
                return res.status(201).send('data added succesfully!');
            }
        });
        
    
}



const login = async(req, res, next) => {
     // 9. komparasi antara password yang diinput oleh pengguna dan password yang ada didatabase
    const {email, password } = req.body;
    if (!(email && password)) {
        return res.status(400).send("All input is required");
    }
    const data = await db.query(`SELECT * FROM unhan_modul_17 WHERE email = $1`, [email])
    if (data.rowCount == 0 ){
        return res.status(401).json({ error: "User does not exist" })
    }else{
        if (bcrypt.compareSync(password, data.rows[0].password)){
            
            // 10. Generate token menggunakan jwt sign
            const token = jwt.sign(
                { id: data.rows[0].id,
                    username: data.rows[0].username,
                    email:data.rows[0].email,
                    password:data.rows[0].password },
                process.env.SECRET,
                {
                    expiresIn: "2h",
                }
            );
            //11. kembalikan nilai id, email, dan username
            return res.cookie("JWT", token, {httpOnly: true,sameSite: "strict"}).status(200).json({
                id: data.rows[0].id,
                username: data.rows[0].username,
                email:data.rows[0].email,
                token: token,
                message: "You are login"
                
            });
        }else{
            return res.status(401).json({ message: "Invalid Credentials" });
        }
    }
    
}

const logout = async(req, res, next) => {
                
    try {
        // 14. code untuk menghilangkan token dari cookies dan mengembalikan pesan "sudah keluar dari aplikasi" 
        const refreshToken = req.cookies.token;
        return res.clearCookie("JWT").status(200).send("You are has been logout");
    } catch (err) {
        console.log(err.message);
        return res.status(500).send(err)
    }
            
}

const verify = async(req, res, next) => {
    try {
        // 13. membuat verify\
        const data = req.data
        return res.status(200).json(data)
    } catch (err) {
        console.log(err.message);
        return res.status(500).send(err);
    }
}

module.exports = {
    register,
    login,
    logout,
    verify
}
