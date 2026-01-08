const jwt = require("jsonwebtoken");

const isLogin = async (req, res, next) => {
    const { check } = req.cookies;

    if (!check) {
        return res.redirect("/auth/signin");
    }

    try {
        const decoded = jwt.verify(check, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.redirect("/auth/signin");
    }
};

module.exports = isLogin;
