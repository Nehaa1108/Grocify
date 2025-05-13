// import connectDB from './connectDB.js';

// const createAddressTable = () => {
//   const sql = `
//     CREATE TABLE IF NOT EXISTS address (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       address_line VARCHAR(255) DEFAULT '',
//       city VARCHAR(100) DEFAULT '',
//       state VARCHAR(100) DEFAULT '',
//       pincode VARCHAR(20),
//       country VARCHAR(100),
//       mobile BIGINT DEFAULT NULL,
//       createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//       updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
//     )
//   `;

//   connectDB.query(sql, (err, result) => {
//     if (err) {
//       console.error("❌ Error creating address table:", err);
//     } else {
//       console.log("✅ Address table created or already exists");
//     }
//   });
// };

// createAddressTable();


import mongoose from "mongoose"

const addressSchema = new mongoose.Schema({
  address_line:
  {
    type:String,
    default:""
},
city:{
  type:String,
  default:""
},
state:{
  type:String,
  default:""
},
pincode:{
  type:String,
},
status:{
  type:Boolean,
  default:true
},
country:{
  type:String,
},
mobile:{
  type:Number,
  default:null
}
},{
  timestamps:true
})

const AddressModel = mongoose.model('address',addressSchema)

export default AddressModel