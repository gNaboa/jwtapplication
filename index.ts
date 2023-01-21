import express,{Request,Response} from 'express'

import {PrismaClient} from '@prisma/client'
import bcrypt from 'bcrypt'
import cookieparser from 'cookie-parser'
import {createUserToken, validateToken} from './JWT'
const app =express()
app.use(express.json())

const prisma = new PrismaClient()


app.post('/api/register',async (req:Request,res:Response)=>{
    
    const {username,password} = req.body

    const hashPassword = await bcrypt.hash(password,10)
    
 try{
   await prisma.user.create({
    data:{
      username:username,
      password:hashPassword
    }
   })
  res.json("USER REGISTERED")
 }
 catch(err){
    res.status(400).json({error:err})
 }
  
})

app.post('/api/login', async (req:Request,res:Response)=>{
  const {username,password} = req.body

   const userExists = await prisma.user.findUnique({
    where:{
      username:username
    }
   })
   if(!userExists){
      res.status(400).json({error:"User doesn't exist"})
   }else{

    const dbPassword = userExists.password
    bcrypt.compare(password,dbPassword).then((match)=>{
        if(!match){
          return res.status(400).json({error:"Wrong password or username"})
        }else{
          
          const accesstoken = createUserToken(userExists)
          res.cookie("access-token",accesstoken,{
            maxAge:60*60*24*30   //30 days
          })

          res.json("USER LOGGED IN")
        }
    })
   }

})

app.get('/api/profile',validateToken,async (req:Request,res:Response)=>{
  
  res.json("PROFILE")
})
app.delete('/api/delete/:id',async (req:Request,res:Response)=>{
      const {id} = req.params  
     try{
        await prisma.user.delete({
          where:{
            id:id
          }
        })

        res.json("USER REMOVED")
     }catch(err){
      res.status(400).json({error:err})
     }
})



app.listen(3001,()=>console.log("App running in port 3001"))