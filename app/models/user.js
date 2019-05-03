const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
var Schema       = mongoose.Schema;

const UserSchema =  new Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

UserSchema.plugin(encrypt, {secret: process.env.MONGO_SECRET, encryptedFields: ['password']});

module.exports = mongoose.model('User', UserSchema);
