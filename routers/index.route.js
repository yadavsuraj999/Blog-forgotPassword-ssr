const express = require("express");
const { index, blogForm, addBlog, viewBlog, deleteBlog, editBlogForm, editBlog, quickBlog } = require("../controllers/blogContoller");
const upload = require("../middleware/multer");
const router = express.Router();

router.get("/", index)
router.get("/add-blog", blogForm);
router.post("/add-blog", upload.single("blogImage"), addBlog)
router.get("/view-blog", viewBlog)
router.get("/delete-blog/:id", deleteBlog);
router.get("/view-blog/:id", quickBlog);
router.get("/edit-blog/:id", editBlogForm);
router.post("/edit-blog/:id", upload.single("blogImage"), editBlog);

module.exports = router