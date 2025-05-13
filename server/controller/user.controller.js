

import sendEmail from '../config/sendEmail.js'
import UserModel from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js';
import generatedAccessToken from '../utils/generatedAccessToken.js';
import generatedRefreshToken from '../utils/generatedRefreshToken.js';
import uploadImageClodinary from '../utils/uploadImageCloudinary.js'
import generatedOtp from '../utils/generatedOtp.js';
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js';

//Regisetr 
export async function registerUserController(req, res) {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Provide name, email, and password",
        error: true,
        success: false
        // data:save
      });
    }

    const User = await UserModel.findOne({ email });

    if (User) {
      return res.json({
        message: "Email already registered",
        error: true,
        success: false
      });
    }

    const salt = await bcryptjs.genSalt(10)
    // FIXED: genSalt not getSalt
    const hashPassword = await bcryptjs.hash(password, salt);

    const payload = {
      name,
      email,
      password: hashPassword
    };

    const newUser = new UserModel(payload);
    const save = await newUser.save(); // FIXED: 'constsave' typo

    const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`;

    const verifyEmail =  await sendEmail({
      sendTo: email,
      subject: "Verification Email from Grocify",
      html: verifyEmailTemplate({
        name,
        url: verifyEmailUrl
      })
    });

    return res.json({
      message: "User registered successfully",
      error: false,
      success: true,
      data : save
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
}


// Email Verification
export async function verifyEmailController(req,res){
  try{
      const { code } = req.body
      const user = await UserModel.findOne({_id : code })

      if(!user){
        return res.status(400).json({
          message:"Invalid code",
          error : true,
          success : false
        })
      }

      const updateUser = await UserModel.updateOne({_id  : code },{
        verify_email : true
      })

      return res.json({
        message : "Verify email done ",
        error : fales,
        success: true
      })
  }
  catch (error)
  {
    //500- for server error
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    })
  }
}

//Login controller
export async function loginController(req,res) {
  try{
    const { email, password } =req.body


    if(!email || !password)
    {
      return res.status(400).json({
        message:"provide email ,password",
        error:true,
        success:false
      })
    }

    const user =  await UserModel.findOne({email})

    if(!user)
    {
      return res.status(400).json({
        message:"User is not register",
        error : true,
        success: false
      })
    }

    if(user.status !== "Active")
    {
      return res.status(400).json({
        message:"Contact to Admin",
        error:true,
        success:false
      })
    }

    const checkPassword = await bcryptjs.compare(password,user.password)
    if (!checkPassword)
    {
      return res.status(400).json({
        message:"Check Your  Password",
        error:true,
        success:false
      })
    }

    //access token
    const accessToken = await generatedAccessToken(user._id)
    const refreshToken = await generatedRefreshToken(user._id)


    const updateUser = await UserModel.findByIdAndUpdate(user?._id,
      {
        last_login_date : new Date()
      }
    )

    const cookiesOption={
      httpOnly:true,
      secure:true,
      //use both frontend and backend site
      sameSite:"None"
    }
    res.cookie('accessToken',accessToken,cookiesOption)
    res.cookie('refreshToken',refreshToken,cookiesOption)

    return res.json({
      message:"Login Successfully",
      error:false,
      success:true,
      data:{
        accessToken,
        refreshToken
      }
    })
  }
  catch (error)
  {
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    })
  }
}

//Logout Controller
export async function logoutController(req,res)
{
  try{

    const userid = req.userId //come from middleware


    const cookiesOption={
      httpOnly:true,
      secure:true,
      //use both frontend and backend site
      sameSite:"None"
    }

    res.clearCookie("accessToken",cookiesOption)
    res.clearCookie("refreshToken",cookiesOption)

//identify the user
//login refresh token show 
//logout refresh token empty
const removeRefreshToken = await UserModel.findByIdAndUpdate(userid,{
  refresh_token: ""
})


    return res.json(
      {
        message:"Logout Successfully",
        error:false,
        success:true
      }
    )
  }
  catch(error)
  {
    return res.status(500).json({
      message:error.message || error,
      error:true,
      success:false
    })
  }
}

//upload user avatar
export async  function uploadAvatar(request,response){
  try {
    //save avatar in db --userId
      const userId = request.userId // auth middlware
      const image = request.file  // multer middleware

      const upload = await uploadImageClodinary(image)
      //help of userid --find user
      const updateUser = await UserModel.findByIdAndUpdate(userId,{
          avatar : upload.url
      })

      return response.json({
          message : "upload profile",
          success : true,
          error : false,
          data : {
              _id : userId,
              avatar : upload.url
          }
      })

  } catch (error) {
      return response.status(500).json({
          message : error.message || error,
          error : true,
          success : false
      })
  }
}

//Update User Details API
export async function updateUserDetails(req,res)
{
  try {
    //user login only they can update
    const userId= req.userId //come from auth middleware
    const { name , email, mobile, password }= req.body
//using userId --uppadte user details

let hashPassword= ""
if(password){
  const salt = await bcryptjs.genSalt(10)
  hashPassword = await bcryptjs.hash(password, salt);
}
const updateUser = await UserModel.updateOne({_id : userId},{
  ...(name && {name : name }),
  ...(email && {email : email }),
  ...(mobile && {mobile : mobile }),
  ...(password && {password : hashPassword})
})

return res.json({
  message:"updated user successfully",
  error:false,
  success:true,
  data:updateUser
})

  } catch (error) {
    return res.status(500).json({
      message:error.message || error,
      error:true,
      success:false
    })
  }
}

//forgot Password API--
export async function forgotPasswordController(req,res)
{
  try {
    const { email } = req.body
    //already register or not--
    const user = await UserModel.findOne({ email })

    if(!user)
    {
      return res.status(400).json({
        message:"Email not available",
        error:true,
        success:false
      })
    }

    const otp=generatedOtp()

    //expire opt then..
    const expireTime = new Date() + 60 * 60 *1000   //1hr

    const update = await UserModel.findByIdAndUpdate(user._id,{
      forgot_password_otp: otp,
      forgot_password_expiry : new Date(expireTime).toISOString()
    })

    await sendEmail({
      sendTo : email,
      subject : "Forgot Password From Grocify",
      html : forgotPasswordTemplate({
        name: user.name,
        otp : otp
      })
    })

    return res.json({
      message:'check your email',
      error:false,
      success:true
    })

  } catch (error) {
    return res.status(500).json({
      message:error.message || error,
      error:true,
      success:false
    })
  }
}

//verify foget password otp--
export async function verifyForgotPasswordOtp(req, res) {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        message: "Provide required fields: email, otp.",
        error: true,
        success: false,
      });
    }

    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.status(400).json({
        message: "Email not available",
        error: true,
        success: false,
      });
    }

    const currentTime = new Date().toISOString();

    if (user.forgot_password_expiry < currentTime) {
      return res.status(400).json({
        message: "OTP expired",
        error: true,
        success: false,
      });
    }

    if (otp !== user.forgot_password_otp) {
      return res.status(400).json({
        message: "Invalid OTP",
        error: true,
        success: false,
      });
    }


    const updateUser = await UserModel.findByIdAndUpdate(user?._id,{
      forgot_password_otp : "",
      forgot_password_expiry :""
    })

    return res.json({
      message: "OTP verified successfully",
      error: false,
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}



//reset password 
export async function resetPasswordController(req,res) {
  try {
    const { email , newPassword , confirmPassword } = req.body
    
    if(!email || !newPassword || !confirmPassword)
    {
      return res.status(400).json({
        message:"provide required fields email, newPassword , confirmPassword",
      })
    }

    const user = await UserModel.findOne({ email })

    if(!user)
    {
      return res.status(400).json({
        message:"Email is not available",
        error:true,
        success:false
      })
    }

    if(newPassword !== confirmPassword){
      return res.status(400).json({
        message:"newPassword and confirmPassword must be same.",
        error:true,
        success:false
      })
    }

    const salt = await bcryptjs.genSalt(10)
    const hashPassword = await bcryptjs.hash(newPassword,salt)

    const update = await UserModel.findByIdAndUpdate(user._id,{
      password : hashPassword
    })

    return res.json({
      message : "Password update Successfully.",
      error:false,
      success:true
    })

  } catch (error) {
    return res.status(500).json({
      message:error.message || error,
      error:true,
      success:false
    })
  }
}

// //Refresh Token API--
export async function refreshToken(request,response){
  // console.log("Hit /api/user/refresh-token");
  // console.log("Exported:", refreshTokenController)
  try {
      const refreshToken = request.cookies.refreshToken || request?.headers?.authorization?.split(" ")[1]  /// [ Bearer token]

      if(!refreshToken){
          return response.status(401).json({
              message : "Invalid token",
              error  : true,
              success : false
          })
      }

      const verifyToken = await jwt.verify(refreshToken,process.env.SECRET_KEY_REFRESH_TOKEN)

      if(!verifyToken){
          return response.status(401).json({
              message : "token is expired",
              error : true,
              success : false
          })
      }

      const userId = verifyToken?._id

      const newAccessToken = await generatedAccessToken(userId)

      const cookiesOption = {
          httpOnly : true,
          secure : true,
          sameSite : "None"
      }

      response.cookie('accessToken',newAccessToken,cookiesOption)

      return response.json({
          message : "New Access token generated",
          error : false,
          success : true,
          data : {
              accessToken : newAccessToken
          }
      })


  } catch (error) {
      return response.status(500).json({
          message : error.message || error,
          error : true,
          success : false
      })
  }
}


//get login user details
export async function userDetails(request,response){
  try {
      const userId  = request.userId

      console.log(userId)

      const user = await UserModel.findById(userId).select('-password -refresh_token')

      return response.json({
          message : 'user details',
          data : user,
          error : false,
          success : true
      })
  } catch (error) {
      return response.status(500).json({
          message : "Something is wrong",
          error : true,
          success : false
      })
  }
}