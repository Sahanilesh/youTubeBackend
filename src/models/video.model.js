import mongoose, {Schema} from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const videoSchema = new Schema(
    {
        videoFile: {
            type: String, // URL to the video file - cloudinary
            required: true,
        },
        thumbnail: {
            type: String, // URL to the thumbnail image - cloudinary
            required: true,
        },
        title: {
            type: String, 
            required: true,
        },
        description: {
            type: String, 
            required: true,
        },
        duration: {
            type: Number, 
            required: true,
        },
        views:{
            type: Number,
            default: 0,
        },
        isPublisehed:{
            type: Boolean,
            default: true,
        },
        owner: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
    },
    {timestamps: true});

videoSchema.plugin(mongooseAggregatePaginate)

export const Video = mongoose.model("Video", videoSchema);