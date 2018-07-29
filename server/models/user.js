const mongoose = require("mongoose")
const bcrypt = require("bcrypt")

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  profileImgUrl: {
    type: String
  },
  messages: [
      {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Message"
    }
  ]
})

// runs before every save of a user
userSchema.pre("save", async function(next) {
  try {
    // if the password has not changed do nothing
    if ( !this.isModified("password") ) {
      return next()
    }
    // if the password has changed hash the password with a salt of 10
    let hashPassword = await bcrypt.hash(this.password, 10)
    this.password = hashPassword
    return next()
  } catch (err) {
    return next(err)
  }
})

// compares login password to saved password
userSchema.methods.comparePassword = async function(candidatePassword, next) {
  try {
    // ismatch will hash the candiadte password and return true if it matches
    // the saved hashed password
    // Used for checking if login password is corrent
    let isMatch = await bcrypt.compare(candidatePassword, this.password)
    // returns true or false
    return isMatch
  } catch (err) {
    return next(err)
  }
}

const User = mongoose.model("User", userSchema)

module.exports = User
