import { error } from "console";
import cookieParser from "cookie-parser";
import express from "express";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import path from "path";
import bcrypt from "bcrypt";

//Server Create
const app = express();

//Server Listen
app.listen(3000, () => {
  console.log(`Server Listen on Port No.3000`);
});

//Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));

//Setting for Engine
app.set("view engine", "ejs");

//Connection to Database
mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "UserRLLApp",
  })
  .then(() => console.log(`Database Connected`))
  .catch((error) => console.log(error));

//Create Schema
const userSchema = mongoose.Schema(
  {
    username: {
      type: String,
      require: true,
    },
    email: {
      type: String,
      require: true,
    },
    password: {
      type: String,
      require: true,
    },
  },
  { timestamps: true }
);

//Create Model
const userModel = mongoose.model("users", userSchema);

//Authentication
const isAuthenticated = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.render("login", { massages: `User Not Login` });
  }
  try {
    const verifyToken = jwt.verify(token, "abcdefghijklmnop");
    req.user = await userModel.findById(verifyToken._id);
    next();
  } catch (error) {
    console.log(error);
    res.render("login", { massages: `User Not Login` });
  }
};

//Root Rout
app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { massages: req.user.username });
});

//Register For User
//Route
app.get("/register", (req, res) => {
  res.render("register");
});

//API
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  let user = await userModel.findOne({ email });
  try {
    if (user) {
      res.render("login", { massages: `User Already register` });
    } else {
      //Password Hashing
      const hashedPassword = await bcrypt.hash(password, 10);
      //Create User
      const user = new userModel({
        username,
        email,
        password: hashedPassword,
      });

      //jsonwebtoken Create
      const token = jwt.sign({ _id: user._id }, "abcdefghijklmnop");
      //cookie Create
      res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000),
      });

      //Save User
      await user.save();
      // res.render("login", { massages: `User Register` });
      res.redirect("/");
    }
  } catch (error) {
    console.log(`error for register ${error}`);
  }
});

//Login For User
//Route for User
app.get("/login", (req, res) => {
  res.render("login");
});

//API For Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let user = await userModel.findOne({ email });

  try {
    if (!user) {
      // res.redirect("/register");
      return res.render("register", { massages: `User Not Register` });
    } else {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.render("login", { massages: `Password Incorrect` });
      }
      const token = jwt.sign({ _id: user._id }, "abcdefghijklmnop");
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        expires: new Date(Date.now() + 60 * 1000),
      });
      // res.render("logout", { massages: `User Login Now` });
      res.redirect("/");
    }
  } catch (error) {
    console.log(error);
  }
});

//Logout For User
app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    secure: true,
    expires: new Date(Date.now()),
  });
  // res.render("login", { massages: `User Logout` });
  res.redirect("/");
});
