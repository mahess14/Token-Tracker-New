import mongoose from "mongoose";

export const PRODUCTS = [
  "HYP2003 token",
  "ePass 2003 token",
  "Proxkey token",
  "mToken",
  "Class 3 DSC + token",
  "DGFT DSC + token",
];

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const saleSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    date: { type: Date, required: true },
    quantity: { type: Number, required: true, min: 1 },
    product: { type: String, required: true, enum: PRODUCTS },
    sellingPrice: { type: Number, required: true, min: 0 },
    customerName: { type: String, default: "", trim: true },
    amount: { type: Number, required: true, min: 0 },
  },
  { timestamps: true }
);

const purchaseSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    date: { type: Date, required: true },
    quantity: { type: Number, required: true, min: 1 },
    product: { type: String, required: true, enum: PRODUCTS },
    costPrice: { type: Number, required: true, min: 0 },
    supplierName: { type: String, default: "", trim: true },
    amount: { type: Number, required: true, min: 0 },
  },
  { timestamps: true }
);

export const User = mongoose.model("User", userSchema);
export const Sale = mongoose.model("Sale", saleSchema);
export const Purchase = mongoose.model("Purchase", purchaseSchema);
