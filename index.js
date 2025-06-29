const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");

const app = express(cors());
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});
app.get("/", (req, res) => {
  res.send("Chat server is running");
});
server.listen(3000, () => {
  console.log("Server is running on port 3000");
});
io.on("connection", (socket) => {
  console.log("A user connected", socket.id);

  socket.on("disconnect", () => {
    console.log("A user disconnected");
  });

  socket.on("message", (msg) => {
    console.log("Message received: " + msg);
    socket.broadcast.emit("message", msg);
  });
});
