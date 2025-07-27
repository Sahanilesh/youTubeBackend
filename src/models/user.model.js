import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema(
    {
        usename : {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
            index: true
        },
        email : {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
        },
        fullName : {
            type: String,
            required: true,
            trim: true,
            index: true
        },
        avatar : {
            type: String, // URL to the avatar image - cloudinary
            required: true,
        },
        coverImage : {
            type: String, // URL to the cover image - cloudinary
        },
        watchHistory : [
            {
                type: Schema.Types.ObjectId,
                ref: "Video"
            }
        ],
        password : {
            type: String,
            required: [true,"Password is required"],
        },
        refreshToken :{
            type: String,
        }
    },
    {timestamps: true});

// Password hashing middleware  
userSchema.pre("save", async function(next) {
    if(!this.isModified("password")){
        return next();
    }
    this.password =  bcrypt.hash(this.password, 10);
    next();
})

userSchema.methods.isPasswordCorrect = async function(password) {
    return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function() {
    return jwt.sign(
        {
            _id: this._id,
            usename: this.usename,
            email: this.email,
            fullName: this.fullName,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRES
        }
    )
}
userSchema.methods.generateRefreshToken = function() {
    return jwt.sign(
    {
        _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRES
    })
}

export const User = mongoose.model("User", userSchema);