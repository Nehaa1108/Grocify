// import mongoose from 'mongoose';
// import dotenv from 'dotenv';

// // Load .env variables first
// dotenv.config();

// if (!process.env.MONGODB_URI) {
//   throw new Error("Please provide MONGODB_URI in the .env file");
// }

// async function connectDB() {
//   try {
//     await mongoose.connect(process.env.MONGODB_URI);
//     console.log("✅ MongoDB connected successfully");
//   } catch (error) {
//     console.error("❌ MongoDB connection error:", error);
//     process.exit(1); // Exit the process if connection fails
//   }
// }

// export default connectDB;



import mongoose from "mongoose";
import dotenv from 'dotenv'
dotenv.config()

if(!process.env.MONGODB_URI){
    throw new Error(
        "Please provide MONGODB_URI in the .env file"
    )
}

async function connectDB(){
    try {
        await mongoose.connect(process.env.MONGODB_URI)
        console.log("connect DB")
    } catch (error) {
        console.log("Mongodb connect error",error)
        process.exit(1)
    }
}

export default connectDB