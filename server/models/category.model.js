import mongoose from 'mongoose'

const catogorySchema =new mongoose.Schema({
  name:{
    type:String,
    default:""
  },
  image:{
    type:String,
    default:""
  }
},{
  timestamps:true
})

const CategoryModel = mongoose.model('category',catogorySchema)

export default CategoryModel