const mongoose = require('mongoose');


const productNotdelivered = new mongoose.Schema({
    email: { type: String, required: true }, 
    message: { type: String, required: true }, 
   DateCreted : {type:Date,default:Date.now},
  });
  
  const Faileddelivery = mongoose.model('faileddeliveries', productNotdelivered);
  
  
  module.exports = Faileddelivery;
  