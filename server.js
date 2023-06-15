import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/final-project";
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.Promise = Promise;

// Defines the port the app will run on. Defaults to 8080, but can be overridden
// when starting the server. Example command to overwrite PORT env variable value:
// PORT=9000 npm start
const port = process.env.PORT || 8080;
const app = express();
const listEndPoints = require('express-list-endpoints');

// Add middlewares to enable cors and json body parsing
app.use(cors());
app.use(express.json());

// User model with validation rules
const { Schema } = mongoose;
const UserSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString("hex")
  }
});
const User = mongoose.model("User", UserSchema);

// Start defining your routes here
app.get("/", (req, res) => {
  res.json(listEndPoints(app));
});

// Register new user
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  const salt = bcrypt.genSaltSync();
  try {
    if (password.length < 8) {
      res.status(400).json({
        success: false,
        response: "Password must be minimum 8 characters"
      });
    } else {
      const newUser = await new User({ username, password: bcrypt.hashSync(password, salt) }).save();
      res.status(201).json({
        success: true,
        response: {
          username: newUser.username,
          accessToken: newUser.accessToken,
          userId: newUser._id
        }
      });
    };
  } catch (e) {
    res.status(400).json({
      success: false,
      response: "Could not create user"
    });
  }
});

// Login as an already registered user
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
      res.status(200).json({
        success: true,
        response: {
          username: user.username,
          accessToken: user.accessToken,
          userId: user._id
        }
      });
    } else {
      res.status(200).json({
        success: false,
        response: "User not found"
      });
    }
  } catch (e) {
    res.status(400).json({
      success: false,
      response: e,
      message: "Something went wrong, please try again."
    });
  }
});

// Middleware function for authentication
const authenticateUser = async (req, res, next) => {
  try {
    // Looks up the user based on the accessToken stored in the header
    const user = await User.findOne({ accessToken: req.header("Authorization") });
    if (user) {
      req.user = user
      // Allows the protected endpoint to continue exec.
      next();
    } else {
      // If no accessToken was found, access will be denied
      res.status(401).json({
        success: false,
        response: "Access denied, please sign in."
      });
    }
  } catch (e) {
    res.status(400).json({
      success: false,
      response: e
    })
  }
};

// The location model
const LocationSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  title: {
    type: String,
    required: true,
  },
  location: {
    type: String,
    required: true,
  },
  tag: {
    type: String,
  },
  createdAt: {
    type: Date,
    default: () => new Date()
  }
});
const Location = mongoose.model("Location", LocationSchema);

// Secret endpoint that only can be accessed when logged in as a user
app.get("/locations", authenticateUser);
app.get("/locations", async(req, res) => {
  try {
    if (req.user) {
      const locations = await Location.find({ user: mongoose.Types.ObjectId(req.user.id)}).sort({ createdAt: -1 });
      res.status(200).json({
        success: true,
        response: locations
      });
    } else {
      res.status(404).json({
        success: false,
        respone: 'Locations not found'
      });
    }
  } catch(e) {
    res.status(400).json({
      success: false,
      respone: e
    });
  }
});

// Post new location
app.post("/locations", async(req, res) => {
  const { title, location, tag } = req.body;
  const { user } = req.user;
  try {
    const newLocation = await Location({ user, title, location, tag}).save();
    res.status(200).json({
      success: true,
      response: newLocation
    });
  } catch(e) {
    res.status(400).json({
      success: false,
      respone: e
    });
  }
});

// Delete location
app.delete("/locations/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const newLocation = await Location.findByIdAndRemove(id);
    res.status(201).json({
      success: true,
      response: newLocation,
      message: "deleted successfully"
    });
  } catch(e) {
    res.status(400).json({
      success: false,
      response: e,
      message: "something went wrong, could not delete"
    });
  }
});

// Edit location
app.patch("/locations/:id/edit", async (req, res) => {
  const { id } = req.params;
  const { title, location, tag } = req.body;
  try {
    const editLocation = await Location.findByIdAndUpdate(id, { title: title, location: location, tag: tag }, { new: true });
    res.status(201).json({
      success: true,
      response: editLocation,
      message: "edited successfully"
    });
  } catch(e) {
    res.status(400).json({
      success: false,
      response: e,
      message: "error occured, could not edit location"
    });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});