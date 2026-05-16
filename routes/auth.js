const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const db = require("../database/db")

const router = express.Router()

const SECRET = "bom_secret_key"

router.post("/register", async (req,res)=>{

 const {username,password} = req.body

 const hash = await bcrypt.hash(password,10)

 db.query(
   "INSERT INTO users(username,password,role) VALUES(?,?,?)",
   [username,hash,"user"],
   (err,result)=>{
      if(err) return res.status(500).json(err)

      res.json({message:"User created"})
   }
 )

})

router.post("/login",(req,res)=>{

 const {username,password} = req.body

 db.query(
   "SELECT * FROM users WHERE username=?",
   [username],
   async (err,result)=>{

     if(result.length==0)
       return res.status(401).json({message:"User not found"})

     const user=result[0]

     const valid=await bcrypt.compare(password,user.password)

     if(!valid)
       return res.status(401).json({message:"Wrong password"})

     const token=jwt.sign(
       {id:user.id,role:user.role},
       SECRET,
       {expiresIn:"8h"}
     )

     res.json({token})
   }
 )

})

module.exports = router
