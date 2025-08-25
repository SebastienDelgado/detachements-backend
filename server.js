const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

app.get('/api/health',(req,res)=>res.json({ok:true}));

app.post('/api/auth/login',(req,res)=>{
  const {email,password}=req.body||{};
  if(email==='admin@csec-sg.com' && password==='Art21!'){
    return res.json({token:'demo-token'});
  }
  return res.status(401).json({error:'Identifiants invalides'});
});

app.listen(PORT,()=>console.log('API listening on '+PORT));
