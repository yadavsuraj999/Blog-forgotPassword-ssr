require("dotenv").config();
const express = require("express");
const connectDB = require("./config/db");
const authRouter = require("./routers/auth.route");
const adminRouter = require("./routers/index.route");
const isLogin = require("./middleware/protectedRout");
const cookieParser = require("cookie-parser");
const clintRouter = require("./routers/clint.route");

const app = express();

connectDB();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));
app.use(cookieParser());

const PORT = process.env.PORT;

app.use("/", clintRouter);
app.use("/auth", authRouter);
app.use("/admin", isLogin, adminRouter);

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
