const { Schema, model } = require("mongoose");

const usersData = new Schema({
    userData: [
        {
            "name": String,
            "email": String,
            "image": String,
            "username":String,
            "password":String,
            "verification":Boolean,
            "resetToken":String||Number,
            "resetTokenExpiry":String||Number,
        },
    ],
})

const UserModel = model("User", usersData);
module.exports = UserModel;
