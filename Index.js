
import express from 'express';
import path from 'path';
import mongoose, { Model } from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from "bcrypt";

const app = express();



//Using Middlewares
app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.set("view engine","ejs");

mongoose.connect("mongodb://127.0.0.1:27017/sample").then(()=>{
    console.log("Connection to db successfull");
}).catch((err)=>
{
    console.log(err);
})



const userSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String
})

const User = new mongoose.model("user",userSchema);
const isAuthenticated = async(req,res,next)=>{
    const {token} = req.cookies;
    if(token)
    {
     
        const decoded =  jwt.verify(token,"secretKey");
        req.user = await User.findById(decoded._id);
        next();
      
    }
    else{
     res.render("login");
    }

}

app.get("/",isAuthenticated,(req,res)=>{
       const {name} = req.user;
       res.render("logout.ejs",{user:name})
})

app.post("/register",async(req,res)=>{
    
   const {name,email,password} = req.body;
   const hashedPassword = await bcrypt.hash(password,10);
   let user = await User.findOne({email});
   if(user)
   {
     res.render("login",{message:"User Already exists"});
   }
   
    user =  await User.create({name,email,password:hashedPassword});
    const token = jwt.sign({_id:user._id},"secretKey")
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    });
       res.redirect("/");
});
app.post("/login",async(req,res)=>{
    const {email,password} = req.body;
    const user = await User.findOne({email});
    if(!user)return res.render("register",{message:"user doesnot exist please register"});
    const isMatched = await bcrypt.compare(user.password,password);
    if(!isMatched)return res.render("login",{message:"incorrect password"});
    const token = jwt.sign({_id:user._id},"secretKey")
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now()+60*1000)
    });
    res.redirect("/");
})

app.get("/logout",(req,res)=>{
    res.cookie("token",null,{
        httpOnly:true,
        expires: new Date(Date.now())
    })
    res.redirect('/');
})


app.listen(3000,()=>{
    console.log("Server is running");
});


