const db = require("../models")
const jwt = require("jsonwebtoken")

exports.signin = async function(req, res,  next){
  // find a user
  try {
    let user = await db.User.findOne({
      email: req.body.email
    })
    let { id, username, profileImgUrl } = user
    let isMatch = await user.comparePassword(req.body.password)
    if (isMatch) {
      let token = jwt.sign({
        id,
        username,
        profileImgUrl
      }, process.env.SECRET_KEY)
      return res.status(200).json({
        id,
        username,
        profileImgUrl,
        token
      })
    } else {
      return next({
        status: 400,
        message: "Invalid Email/Password."
      })
    }
  } catch (err) {
    return next({
      status: 400,
      message: "Invalid Email/Password."
    })
  }

}

exports.signup = async function(req, res, next){
  try {
    // create a user
    let user = await db.User.create(req.body)
    let { id, username, profileImgUrl } = user
    // create (sign) a token
    let token = jwt.sign(
      {
        id,
        username,
        profileImgUrl
      },
      process.env.SECRET_KEY
    )
    return res.status(200).json({
      id,
      username,
      profileImgUrl,
      token
    })
  } catch (err) {
    // see what kind of error
    // if validation fails
    if(err.code === 11000) {
      err.message = "Sorry, that username and/or username is taken"
    }
    // otherwise just send back a generic 400
    return next({
      status: 400,
      message: err.message
    })
  }
}
