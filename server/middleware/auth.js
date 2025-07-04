import jwt from 'jsonwebtoken'
const auth= async(req,res,next)=>
{
try {
  const token = req.cookies.accessToken || req?.headers?.authorization?.split(" ")[1]
   ///["bearer"," token"}
  console.log("token",token)
 

  //verify token is valid or not
  if(!token){
    return res.status(401).json({
      message:"provide token",

    })
  }

  const decode = await jwt.verify(token,process.env.SECRET_KEY_ACCESS_TOKEN)
  //expire
  if (!decode)
  {
    res.status(401).json({
      message:"unauthorized access",
      error:true,
      success:false
    })
  }

  req.userId = decode.id
  next()
  //  console.log('decord',decode)

} catch (error) {
  return res.status(500).json({
    message:error.message || error,
    error:true,
    success:false
  })
}
}

export default auth