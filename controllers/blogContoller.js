const BlogModel = require("../models/blogModle");
const UserModel = require("../models/userModle");
const fs = require("fs");
const path = require("path");

const index = async (req, res) => {
    try {
        const user = await UserModel.findById(req.user.id).select("userName userEmail");

        const blogCount = await BlogModel.countDocuments({
            userId: req.user.id
        });

        res.render("index", {
            user,
            blogCount
        });
    } catch (error) {
        console.log(error);
        res.redirect("/auth/signin");
    }
};



const blogForm = (req, res) => {
    try {
        res.render("addblog")
    } catch (error) {
        console.log(error);
    }
}

const viewBlog = async (req, res) => {
    try {
        const blogs = await BlogModel.find({ userId: req.user.id });
        res.render("viewBlog", { blogs });
    } catch (error) {
        console.log(error);
    }
};


const addBlog = async (req, res) => {
    try {
        const { path } = req.file;
        const blogData = new BlogModel({ ...req.body, blogImage: path, userId: req.user.id });
        await blogData.save();
        res.redirect("/admin/view-blog");
    } catch (error) {
        console.log(error)
    }
}

const deleteBlog = async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await BlogModel.findById(id);

        if (blog) {
            const imagePath = path.join(__dirname, '..', blog.blogImage);
            fs.unlink(imagePath, (err) => {
                if (err) {
                    console.log("Error deleting image: ", err);
                } else {
                    console.log("Image deleted successfully");
                }
            });
            await BlogModel.findOneAndDelete({
                _id: id,
                userId: req.user.id
            });
            res.redirect("/admin/view-blog");
        } else {
            res.redirect("/admin/view-blog");
        }
    } catch (error) {
        console.log(error);
    }
};

const editBlogForm = async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await BlogModel.findById(id);
        if (!blog) {
            return res.redirect("/admin/view-blog");
        }
        res.render("edit", { blog });
    } catch (error) {
        console.log(error);
    }
};

const editBlog = async (req, res) => {
    try {
        let { id } = req.params;
        let updatedData = req.body;

        if (req.file) {
            let data = await BlogModel.findById(id);
            let imgPath = path.join(__dirname, "..", data?.blogImage);
            fs.unlink(imgPath, (err) => {
                if (err) {
                    console.log("Error deleting old image: ", err);
                } else {
                    console.log("Old image deleted successfully");
                }
            });

            updatedData.blogImage = req.file.path;
        }

        await BlogModel.findByIdAndUpdate(id, updatedData);
        res.redirect("/admin/view-blog");
    } catch (error) {
        console.log(error);
        res.redirect("/admin/view-blog");
    }
}

const quickBlog = async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await BlogModel.findById(id);
        return res.render("quickView", { blog });

    } catch (error) {
        console.error(error);
    }
};








module.exports = { index, blogForm, addBlog, viewBlog, deleteBlog, editBlogForm, editBlog, quickBlog };


