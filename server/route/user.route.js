import { Router } from 'express'
import { forgotPasswordController, loginController , logoutController, 
  refreshToken, 
  // refreshTokenController, 
  
  registerUserController, resetPasswordController, updateUserDetails, uploadAvatar, userDetails, verifyEmailController, verifyForgotPasswordOtp } from '../controller/user.controller.js'
import auth from '../middleware/auth.js'
import upload from '../middleware/multer.js'
const userRouter = Router()


// registration API--
userRouter.post('/register',registerUserController)

export default userRouter


// Verify Email API--
userRouter.post('/verify-email',verifyEmailController)



// Login API--
userRouter.post('/login',loginController)

//Logout API--
userRouter.get('/logout',auth,logoutController)

//image--Avatar API--
userRouter.put('/upload-avatar',auth,upload.single('avatar'),uploadAvatar)
//put-bcz update some fields
//auth --only auth access


//user update details API --
userRouter.put('/update-user',auth,updateUserDetails)

//forgot password API--
userRouter.put('/forgot-password',forgotPasswordController)

//verify forgot password otp--
userRouter.put('/verify-forgot-password-otp',verifyForgotPasswordOtp)

//reset password API--
userRouter.put('/reset-password',resetPasswordController)

// //refresh token API--
userRouter.post('/refresh-token',refreshToken)


//user details API--
userRouter.get('/user-details',auth,userDetails)


