const express = require("express")
const clientPage = require("../controllers/clintController")
const router = express.Router()

router.get("/",clientPage)

module.exports = router