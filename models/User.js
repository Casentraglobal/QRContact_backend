import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: { type: String },
    email: { type: String, required: true, unique: true },

    // local auth
    password: { type: String },

    // provider-based auth
    provider: {
      type: String,
      enum: ["local", "google", "apple", "sso"],
      default: "local",
    },
    providerId: { type: String } // google sub / apple sub / sso user id
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);
