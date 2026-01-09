const express = require("express");
const { index, blogForm, addBlog, viewBlog, deleteBlog, editBlogForm, editBlog, quickBlog } = require("../controllers/blogContoller");
const upload = require("../middleware/multer");
const UserModel = require("../models/userModle");
const router = express.Router();
const bcrypt = require("bcrypt");

router.get("/", index)
router.get("/add-blog", blogForm);
router.get("/view-blog", viewBlog)
router.get("/delete-blog/:id", deleteBlog);
router.get("/view-blog/:id", quickBlog);
router.get("/edit-blog/:id", editBlogForm);
router.get("/change-password", (req, res) => {
    res.render("changePassword")
});
router.post("/change-password", async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body;

        const user = await UserModel.findById(req.user.id);
        if (!user) {
            return res.status(404).send("User not found");
        }

        const isValidPassword = await bcrypt.compare(
            oldPassword,
            user.userPassword
        );

        if (!isValidPassword) {
            return res.send("Current password is wrong");
        }

        if (newPassword !== confirmPassword) {
            return res.send("New password and confirm password do not match");
        }

        const newHashedPassword = await bcrypt.hash(newPassword, 10);
        user.userPassword = newHashedPassword;
        await user.save();

        res.redirect("/auth/signin");
    } catch (error) {
        console.error(error);
    }
});


router.post("/edit-blog/:id", upload.single("blogImage"), editBlog);
router.post("/add-blog", upload.single("blogImage"), addBlog)

module.exports = router