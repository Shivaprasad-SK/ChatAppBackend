// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const http = require("http");
const socketIo = require("socket.io");
const QRCode = require("qrcode");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "https://chat-zeta-red-76.vercel.app/",
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// Middleware
app.use(
  cors({
    origin: "https://chat-zeta-red-76.vercel.app/",
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(express.json());

// MongoDB connection
(async () => {
  try {
    await mongoose.connect(
      process.env.MONGODB_URI
    );
    console.log("MongoDB connected successfully");
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
})();

// User Schema
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    uniqueId: {
      type: String,
      unique: true,
      required: true,
      autoincrement: true,
    },
    avatar: { type: String, default: "" },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    friendRequests: [
      {
        from: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        status: {
          type: String,
          enum: ["pending", "accepted", "rejected"],
          default: "pending",
        },
      },
    ],
    isOnline: { type: Boolean, default: false },
    lastSeen: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Message Schema
const messageSchema = new mongoose.Schema(
  {
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    receiver: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    content: { type: String, required: true },
    messageType: {
      type: String,
      enum: ["text", "image", "file"],
      default: "text",
    },
    isRead: { type: Boolean, default: false },
    readAt: { type: Date },
  },
  { timestamps: true }
);

// Conversation Schema
const conversationSchema = new mongoose.Schema(
  {
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: "Message" },
    lastMessageTime: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);
const Conversation = mongoose.model("Conversation", conversationSchema);

// Generate unique ID for user
const generateUniqueId = () => {
  return Math.random().toString(36).substr(2, 9).toUpperCase();
};

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// Auth Routes
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const uniqueId = generateUniqueId();
    const user = new User({
      username,
      email,
      password: hashedPassword,
      uniqueId,
    });

    await user.save();

    // Generate QR code
    const qrCode = await QRCode.toDataURL(uniqueId);

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, "your-secret-key");

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        uniqueId: user.uniqueId,
        qrCode,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // Update online status
    user.isOnline = true;
    await user.save();

    // Generate QR code
    const qrCode = await QRCode.toDataURL(user.uniqueId);

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, "your-secret-key");

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        uniqueId: user.uniqueId,
        qrCode,
      },
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Friend Routes
app.post("/api/send-friend-request", authenticateToken, async (req, res) => {
  try {
    const { uniqueId } = req.body;
    const senderId = req.user.userId;

    // Find target user
    const targetUser = await User.findOne({ uniqueId });
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    if (targetUser._id.toString() === senderId) {
      return res
        .status(400)
        .json({ error: "Cannot send friend request to yourself" });
    }

    // Check if already friends
    const sender = await User.findById(senderId);
    if (sender.friends.includes(targetUser._id)) {
      return res.status(400).json({ error: "Already friends" });
    }

    // Check if request already exists
    const existingRequest = targetUser.friendRequests.find(
      (req) => req.from.toString() === senderId
    );
    if (existingRequest) {
      return res.status(400).json({ error: "Friend request already sent" });
    }

    // Add friend request
    targetUser.friendRequests.push({ from: senderId });
    await targetUser.save();

    res.json({ message: "Friend request sent successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/accept-friend-request", authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.body;
    const userId = req.user.userId;

    const user = await User.findById(userId);
    const requestIndex = user.friendRequests.findIndex(
      (req) => req._id.toString() === requestId
    );

    if (requestIndex === -1) {
      return res.status(404).json({ error: "Friend request not found" });
    }

    const request = user.friendRequests[requestIndex];
    const friendId = request.from;

    // Add to friends list
    user.friends.push(friendId);
    user.friendRequests.splice(requestIndex, 1);
    await user.save();

    // Add to sender's friends list
    const friend = await User.findById(friendId);
    friend.friends.push(userId);
    await friend.save();

    res.json({ message: "Friend request accepted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/friends", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .populate("friends", "username email uniqueId isOnline lastSeen")
      .populate("friendRequests.from", "username email uniqueId");

    res.json({
      friends: user.friends,
      friendRequests: user.friendRequests,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Message Routes
app.get("/api/conversations", authenticateToken, async (req, res) => {
  try {
    const conversations = await Conversation.find({
      participants: req.user.userId,
    })
      .populate("participants", "username email isOnline lastSeen")
      .populate("lastMessage")
      .sort({ lastMessageTime: -1 });

    // res.json(conversations);
    const conversationsWithUnread = await Promise.all(
      conversations.map(async (conv) => {
        const friend = conv.participants.find(
          (p) => p._id.toString() !== req.user.userId
        );
        const unreadCount = await Message.countDocuments({
          sender: friend._id,
          receiver: req.user.userId,
          isRead: false,
        });
        return {
          ...conv,
          unreadCount,
        };
      })
    );

    res.json(conversationsWithUnread);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/messages/:friendId", authenticateToken, async (req, res) => {
  try {
    const { friendId } = req.params;
    const userId = req.user.userId;

    const messages = await Message.find({
      $or: [
        { sender: userId, receiver: friendId },
        { sender: friendId, receiver: userId },
      ],
    })
      .populate("sender receiver", "username")
      .sort({ createdAt: 1 });

    // Mark messages as read
    await Message.updateMany(
      { sender: friendId, receiver: userId, isRead: false },
      { isRead: true, readAt: new Date() }
    );

    res.json(messages);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.io connection handling
const connectedUsers = new Map();

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("user_connected", async (userId) => {
    connectedUsers.set(userId, socket.id);

    // Update user online status
    await User.findByIdAndUpdate(userId, { isOnline: true });

    // Broadcast to friends that user is online
    const user = await User.findById(userId).populate("friends");
    user.friends.forEach((friend) => {
      const friendSocketId = connectedUsers.get(friend._id.toString());
      if (friendSocketId) {
        io.to(friendSocketId).emit("friend_online", {
          userId,
          username: user.username,
        });
      }
    });
  });

  socket.on("send_message", async (data) => {
    try {
      console.log("Send message event received:", data);
      const { senderId, receiverId, content, messageType = "text" } = data;

      // Create message
      const message = new Message({
        sender: senderId,
        receiver: receiverId,
        content,
        messageType,
      });
      await message.save();
      console.log("Attempting to save message:", {
        senderId,
        receiverId,
        content,
      });
      console.log("Message saved to DB:", message);
      // Update or create conversation
      let conversation = await Conversation.findOne({
        participants: { $all: [senderId, receiverId] },
      });

      if (!conversation) {
        conversation = new Conversation({
          participants: [senderId, receiverId],
          lastMessage: message._id,
          lastMessageTime: new Date(),
        });
      } else {
        conversation.lastMessage = message._id;
        conversation.lastMessageTime = new Date();
      }
      await conversation.save();

      // Populate message for sending
      const populatedMessage = await Message.findById(message._id).populate(
        "sender receiver",
        "username"
      );

      // Send to receiver if online
      const receiverSocketId = connectedUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("receive_message", populatedMessage);
      }

      // Send back to sender for confirmation
      socket.emit("message_sent", populatedMessage);
      // io.to(receiverId).emit("receive_message", message);
      // io.to(senderId).emit("message_sent", message);
    } catch (error) {
      socket.emit("error", { message: error.message });
    }
  });

  socket.on("typing", (data) => {
    const { receiverId, isTyping, senderName } = data;
    const receiverSocketId = connectedUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("user_typing", { isTyping, senderName });
    }
  });

  socket.on("disconnect", async () => {
    console.log("User disconnected:", socket.id);

    // Find and remove user from connected users
    for (let [userId, socketId] of connectedUsers.entries()) {
      if (socketId === socket.id) {
        connectedUsers.delete(userId);

        // Update user offline status
        await User.findByIdAndUpdate(userId, {
          isOnline: false,
          lastSeen: new Date(),
        });

        // Broadcast to friends that user is offline
        const user = await User.findById(userId).populate("friends");
        if (user) {
          user.friends.forEach((friend) => {
            const friendSocketId = connectedUsers.get(friend._id.toString());
            if (friendSocketId) {
              io.to(friendSocketId).emit("friend_offline", {
                userId,
                username: user.username,
              });
            }
          });
        }
        break;
      }
    }
  });
});

// socket.on("mark_messages_read", async ({ conversationId, userId }) => {
//   try {
//     await Message.updateMany(
//       { conversationId, receiverId: userId, isRead: false },
//       { $set: { isRead: true } }
//     );
//   } catch (err) {
//     console.error("Error marking messages as read:", err);
//   }
// });

app.get("/api/unread-friends", authenticateToken, async (req, res) => {
  try {
    // Replace Message with your actual Mongoose model for messages
    const unreadMessages = await Message.find({
      receiver: req.user.userId,
      isRead: false,
    }).select("sender");

    // Get unique sender IDs
    const unreadFriendIds = [
      ...new Set(unreadMessages.map((msg) => msg.sender.toString())),
    ];

    res.json({ unreadFriendIds });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Package.json dependencies needed:
/*
{
  "name": "chat-app-backend",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "socket.io": "^4.7.2",
    "qrcode": "^1.5.3"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
*/
