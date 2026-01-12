const BlogModel = require("../models/blogModle");
const clientPage = async (req, res) => {
    try {
        const blogs = await BlogModel.find();
        console.log(blogs);
        res.render("home", { blogs });
    } catch (error) {
        console.log(error);
        res.status(500).send("Server Error");
    }
}

module.exports = clientPage