//1
import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
dotenv.config()
//4
import cookieParser from 'cookie-parser';






//6
import morgan from 'morgan'
import helmet from 'helmet'
import connectDB from './config/connectDB.js';
import userRouter from './route/user.route.js';
import categoryRouter from './route/Category.route.js';
import uploadRouter from './route/upload.router.js';
import subCategoryRouter from './route/subCategory.route.js';
import productRouter from './route/product.route.js';
const app = express()

app.use(cors(
  {
    credentials: true,
    origin: process.env.FRONTEND_URL

  }
))
//3
// app.use(express.json())
app.use(express.json());
//5
app.use(cookieParser())
app.use(morgan('dev')); // or 'combined'

app.use(helmet({
crossOriginResourcePolicy: false
}))

const PORT = 8080 || process.env.PORT


//6
app.get("/",(req,res)=>
{
  // server to client
  res.json({
    message:"Server is running "  + PORT
  })
})

app.use('/api/user',userRouter)
app.use('/api/category',categoryRouter)
app.use("/api/file",uploadRouter)
app.use("/api/subcategory",subCategoryRouter)
app.use("/api/product/",productRouter)
connectDB()


app.listen(PORT,()=>
{
  console.log("server is running ",PORT)
})









































// //2
// FRONTEND_URL = "http://localhost:3000"

//  MONGODB_URI=mongodb+srv://Admin:mongoDB1108@grocify.okrltm1.mongodb.net/?retryWrites=true&w=majority&appName=Grocify
// #  mongodb+srv://Admin:mongoDB1108@grocify.okrltm1.mongodb.net/?retryWrites=true&w=majority&appName=Grocify

//  RESEND_API = re_f8QnCVim_9pfQuHz4qUDeeoZyu57dQhPQ

// SECRET_KEY_ACCESS_TOKEN=qwertyuiopasdfghjklzxcvbnm

// SECRET_KEY_REFRESH_TOKEN=mnbvcxzlkjhgfdsapoiuytrewq

// CLOUDINARY_CLOUD_NAME= dd5jfshk5

// CLOUDINARY_API_KEY = 299758856489998

// CLOUDINARY_API_SECRET_KEY = vAUYw4mUGot7W6EaXzVeBjWAk0Q
// #  npm install resend 


// # DB_HOST=localhost
// # DB_USER=root
// # DB_PASSWORD="Mysql@1108"
// # DB_NAME=groceryshop
// # DB_PORT=3306



// # autogenerate password --->MAE48nsrQysE5w11