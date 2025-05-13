// import mongoose from "mongoose";

// const cartProductSchema = new mongoose.Schema({
//   productId:{
//     type:mongoose.Schema.ObjectId,
//     ref:'pproduct'
//   },
//   quantity:{
//     type:Number,
//     default:1
//   },
//   userId:{
//     type:mongoose.Schema.ObjectId,
//     ref:"User"
//   }
// },{
//   timestamps:true
// })

// const cartProductModel = mongoose.model('cartProduct',cartProductSchema)
// export default cartProductModel



import mongoose from "mongoose";

const cartProductSchema = new mongoose.Schema({
  productId:{
    type:mongoose.Schema.ObjectId,
    ref:'pproduct'
  },
  quantity:{
    type:Number,
    default:1
  },
  userId:{
    type:mongoose.Schema.ObjectId,
    ref:"User"
  }
},{
  timestamps:true
})

const cartProductModel = mongoose.model('cartProduct',cartProductSchema)
export default cartProductModel