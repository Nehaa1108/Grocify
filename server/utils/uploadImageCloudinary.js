import { v2 as cloudinary } from 'cloudinary';

//CREDENTIALS--
cloudinary.config({
  cloud_name : process.env.CLOUDINARY_CLOUD_NAME,
  api_key :  process.env.CLOUDINARY_API_KEY,
  api_secret :  process.env.CLOUDINARY_API_SECRET_KEY
})

const uploadImageCloudinary = async(image)=>
{
//convert image into buffer
const buffer = image?.buffer || Buffer.from(await image.arrayBuffer())

//upload image on clodinary
const uploadImage = await new Promise((resolve,reject)=>{
cloudinary.uploader.upload_stream({folder : "grocify" },(error,uploadResult)=>
{
  return resolve(uploadResult)
}).end(buffer)
})

return uploadImage
}

export default uploadImageCloudinary