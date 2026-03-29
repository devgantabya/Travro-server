const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

/* ================= MONGO CLIENT ================= */
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.7smyhy0.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

let db, usersCollection, destinationsCollection, hotelsCollection, roomsCollection, flightsCollection, bookingsCollection, paymentsCollection;

async function connectDB() {
    try {
        await client.connect();
        db = client.db("travro_db");

        usersCollection = db.collection("users");
        destinationsCollection = db.collection("destinations");
        hotelsCollection = db.collection("hotels");
        roomsCollection = db.collection("rooms");
        flightsCollection = db.collection("flights");
        bookingsCollection = db.collection("bookings");
        paymentsCollection = db.collection("payments");

        console.log("Connected to MongoDB!");
    } catch (err) {
        console.error(err);
    }
}
connectDB();

/* ================= MIDDLEWARE ================= */
const protect = async (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ message: "Invalid token" });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== "admin") return res.status(403).json({ message: "Access denied" });
    next();
};

/* ================= ROUTES ================= */

// Health check
app.get("/", (req, res) => {
    res.send("Hello World!");
});

/* -------- AUTH -------- */
// Register
app.post("/api/auth/register", async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const exist = await usersCollection.findOne({ email });
        if (exist) return res.status(400).json({ message: "User already exists" });

        const hashed = await bcrypt.hash(password, 10);

        const result = await usersCollection.insertOne({ name, email, password: hashed, role: role || "user" });
        res.json(result);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Login
app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(400).json({ message: "User not found" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: "Invalid password" });

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });
        res.json({ token, user: { _id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

/* -------- USERS -------- */
app.get("/api/users", protect, isAdmin, async (req, res) => {
    const users = await usersCollection.find().toArray();
    res.json(users);
});

app.get("/api/users/me", protect, async (req, res) => {
    const user = await usersCollection.findOne({ _id: ObjectId(req.user.id) }, { projection: { password: 0 } });
    res.json(user);
});

app.put("/api/users/me", protect, async (req, res) => {
    const { name, avatar } = req.body;
    const updated = await usersCollection.findOneAndUpdate(
        { _id: ObjectId(req.user.id) },
        { $set: { name, avatar } },
        { returnDocument: "after", projection: { password: 0 } }
    );
    res.json(updated.value);
});

/* -------- BOOKINGS / ORDERS -------- */
app.get("/api/bookings", protect, async (req, res) => {
    if (req.user.role === "user") {
        const orders = await bookingsCollection.find({ userId: req.user.id }).toArray();
        return res.json(orders);
    } else if (req.user.role === "admin") {
        const allOrders = await bookingsCollection.find().toArray();
        return res.json(allOrders);
    }
});

/* -------- ANALYTICS -------- */
app.get("/api/analytics", protect, isAdmin, async (req, res) => {
    const totalUsers = await usersCollection.countDocuments();
    const totalBookings = await bookingsCollection.countDocuments();

    const totalRevenueAgg = await paymentsCollection.aggregate([
        { $group: { _id: null, totalRevenue: { $sum: "$amount" } } },
    ]).toArray();

    res.json({
        totalUsers,
        totalBookings,
        totalRevenue: totalRevenueAgg[0]?.totalRevenue || 0,
    });
});

/* ================= START SERVER ================= */
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});