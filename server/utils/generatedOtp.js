const generatedOtp = ()=>
{
   //0 to 999999
  return Math.floor(Math.random()*900000) + 100000

}
export default generatedOtp