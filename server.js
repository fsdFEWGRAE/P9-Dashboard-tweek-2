const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.use(express.json());
app.use(express.static(__dirname));

// ===== Env Vars =====
const ADMIN_KEY = process.env.ADMIN_KEY;
const API_KEY = process.env.API_KEY;

const USERS_FILE = path.join(__dirname,"users.json");

function loadUsers(){
  if(!fs.existsSync(USERS_FILE)) return {};
  return JSON.parse(fs.readFileSync(USERS_FILE,"utf8"));
}
function saveUsers(u){
  fs.writeFileSync(USERS_FILE, JSON.stringify(u,null,2));
}

// Protect admin endpoints
app.use("/admin",(req,res,next)=>{
  if(req.headers["x-admin-key"] !== ADMIN_KEY){
    return res.status(403).json({ok:false,error:"BAD_ADMIN_KEY"});
  }
  next();
});

// Protect api endpoints for loader
app.use("/api",(req,res,next)=>{
  if(req.headers["x-api-key"] !== API_KEY){
    return res.status(403).json({ok:false, code:"INVALID_API_KEY"});
  }
  next();
});

// login api
app.post("/api/login",(req,res)=>{
  const {username,password,hwid}=req.body;
  const users=loadUsers();
  if(!users[username]) return res.json({ok:false,code:"INVALID_USER"});
  if(users[username].password!==password) return res.json({ok:false,code:"BAD_PASS"});
  if(users[username].disabled) return res.json({ok:false,code:"DISABLED"});

  if(!users[username].hwid){
    users[username].hwid=hwid;
    saveUsers(users);
    return res.json({ok:true});
  }
  if(users[username].hwid!==hwid) return res.json({ok:false,code:"HWID_MISMATCH"});
  res.json({ok:true});
});

// admin
app.get("/admin/list",(req,res)=>res.json(loadUsers()));

app.post("/admin/addUser",(req,res)=>{
  const {username,password}=req.body;
  const u=loadUsers();
  if(u[username]) return res.json({ok:false});
  u[username]={password,hwid:null,disabled:false};
  saveUsers(u);
  res.json({ok:true});
});

app.post("/admin/disableUser",(req,res)=>{
  const {username}=req.body;
  const u=loadUsers();
  if(!u[username]) return res.json({ok:false});
  u[username].disabled=true; saveUsers(u);
  res.json({ok:true});
});

app.post("/admin/resetHwid",(req,res)=>{
  const {username}=req.body;
  const u=loadUsers();
  if(!u[username]) return res.json({ok:false});
  u[username].hwid=null; saveUsers(u);
  res.json({ok:true});
});

app.listen(5055,()=>console.log("Dashboard API running with ENV protection"));
