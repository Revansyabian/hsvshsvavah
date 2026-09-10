import express from "express";
import app from "./api/index.js";

const server = express();

server.use(app);

export default server;

if (process.env.NODE_ENV !== "production") {
  const port = Number(process.env.PORT || 3000);

  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });
}