import nodemailer from "nodemailer";
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import multer from "multer";
import dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import path from "path";
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());


app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
});

app.use("/uploads", express.static(path.join(process.cwd(), "uploads"), {
  setHeaders: (res) => {
      res.set("Cross-Origin-Resource-Policy", "cross-origin");
  },
}));

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
// // Multer Storage
// const storage = multer.diskStorage({
//     destination: "./uploads/",
//     filename: (req, file, cb) => {
//         cb(null, Date.now() + "-" + file.originalname);
//     },
// });

// const upload = multer({ storage });
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
      cb(null, "uploads/");  // Save files in "uploads" folder
  },
  filename: function (req, file, cb) {
      cb(null, Date.now() + "-" + file.originalname); // Unique filenames
  }
});

const upload = multer({ storage });

import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.get("/", (req, res) => {
    res.send("Backend is working fine");
  });
  
  // 📌 Connect to MongoDB
  mongoose
    .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ MongoDB Atlas Connected Successfully"))
    .catch((err) => console.error("❌ MongoDB Connection Error:", err));
  

    const userSchema = new mongoose.Schema({
        firstName: String,
        lastName: String,
        email: { type: String, unique: true, required: true },
        mobile: String,
        password: String,
        otp: String,
        otpExpires: Date, // ✅ OTP expiration time
        isVerified: { type: Boolean, default: false },
      
      });
      
      
      const User = mongoose.model("User", userSchema);

// 📌 Generate OTP function
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// 📩 Send OTP Email
const sendOTPEmail = (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP is: ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) console.log(error);
    else console.log("Email sent: " + info.response);
  });
};

// 📝 Register Route
app.post("/register", async (req, res) => {
    const { firstName, lastName, email, mobile, password } = req.body;
  
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) return res.status(400).json({ message: "User already exists" });
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const otp = generateOTP();
  
      const newUser = new User({
        firstName,
        lastName,
        email,
        mobile,
        password: hashedPassword,
        otp,
        isVerified: false,
      });
  
      await newUser.save();
  
      sendOTPEmail(email, otp);
      res.status(201).json({ message: "OTP sent to email" });
    } catch (error) {
      res.status(500).json({ message: "Server Error" });
    }
  });
  
// 🔹 OTP Verification Route
app.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ message: "User not found" });
  
      if (user.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });
  
      user.isVerified = true;
      user.otp = null;
      await user.save();
  
      res.json({ message: "Verification successful, you can now login" });
    } catch (error) {
      res.status(500).json({ message: "Server Error" });
    }
  });
  
  // 🔐 Login Route
  app.post("/login", async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(400).json({ message: "User not found" });
      if (!user.isVerified) return res.status(400).json({ message: "Please verify your email first" });
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });
  
      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });
      res.json({ token, user: { firstName: user.firstName, email: user.email } });
    } catch (error) {
      res.status(500).json({ message: "Server Error" });
    }
  });



// // Complaint Model
// const Complaint = mongoose.model("Complaint", new mongoose.Schema({
//     text: String,
//     imageUrl: String,
// }));

// // Routes
// app.post("/complaints", upload.single("image"), async (req, res) => {
//     try {
//         const { text } = req.body;
//         const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

//         const complaint = new Complaint({ text, imageUrl });
//         await complaint.save();

//         res.json({ message: "Complaint submitted", complaint });
//     } catch (error) {
//         res.status(500).json({ error: "Something went wrong" });
//     }
// });

// app.get("/complaints", async (req, res) => {
//     const complaints = await Complaint.find();
//     res.json(complaints);
// });

  

// Complaint Model
const Complaint = mongoose.model("Complaint", new mongoose.Schema({
  text: { type: String, required: true },
  imageUrl: String,
  status: { type: String, enum: ["Pending", "Resolved"], default: "Pending" },
  createdAt: { type: Date, default: Date.now }
}));

// API: Submit a Complaint (Default: "Pending")
app.post("/complaints", upload.single("image"), async (req, res) => {
  try {
      const { text } = req.body;
      const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

      const complaint = new Complaint({ text, imageUrl, status: "Pending" });
      await complaint.save();

      res.status(201).json({ message: "Complaint submitted", complaint });
  } catch (error) {
      res.status(500).json({ error: "Something went wrong" });
  }
});

// API: Get All Complaints
app.get("/complaints", async (req, res) => {
  try {
      const complaints = await Complaint.find();
      res.json(complaints);
  } catch (error) {
      res.status(500).json({ error: "Server error" });
  }
});

// API: Get Only Pending Complaints
app.get("/complaints/pending", async (req, res) => {
  try {
      const pendingComplaints = await Complaint.find({ status: "Pending" });
      res.json(pendingComplaints);
  } catch (error) {
      res.status(500).json({ error: "Server error" });
  }
});


// API: Update Complaint Status (Admin Only)
// app.put("/complaints/:id", async (req, res) => {
//   try {
//       const { status } = req.body;
//       const updatedComplaint = await Complaint.findByIdAndUpdate(
//           req.params.id,
//           { status },
//           { new: true }
//       );

//       if (!updatedComplaint) {
//           return res.status(404).json({ error: "Complaint not found" });
//       }

//       res.json({ message: "Complaint updated", complaint: updatedComplaint });
//   } catch (error) {
//       res.status(500).json({ error: "Server error" });
//   }
// });

app.put("/complaints/update/:id", async (req, res) => {
  try {
      const { status } = req.body;
      const updatedComplaint = await Complaint.findByIdAndUpdate(
          req.params.id,
          { status },
          { new: true }
      );
      res.json(updatedComplaint);
  } catch (error) {
      res.status(500).json({ error: "Failed to update status" });
  }
});

// 🚀 Start Server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
