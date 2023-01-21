import {sign,verify} from 'jsonwebtoken'
import {Request,Response} from 'express'

type UserProps={
    id?:string,
    username:string,
    password:string,
}

export function createUserToken({id,username,password}:UserProps){
    
    const accessToken = sign({
        id:id,
        username:username,
        password:password
    },"jwtsecretchange")

    return accessToken
}

export function validateToken(req:Request, res:Response){
  
    const accessToken = req.cookies["access-token"]

    if(!accessToken){
        return res.status(400).json({error:"User not Authenticated"})
    }
    try{
        const isTokenValid = verify(accessToken,"jwtsecretchange")
        if(isTokenValid){
             res.json("User Authenticated")
   
        }
    }catch(err){
        return res.status(400).json({error:err})
    }

}     

