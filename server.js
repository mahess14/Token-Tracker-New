import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User, Sale, Purchase, PRODUCTS } from "./models.js";

dotenv.config();

/* =========================== CONFIG =========================== */
// Secrets come ONLY from environment variables (.env locally, Render → Environment in production).
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;
// Comma-separated list, e.g. "https://my-site.netlify.app,http://localhost:5173"
const FRONTEND_URL = process.env.FRONTEND_URL || "";

if (!MONGO_URI || !JWT_SECRET) {
  console.error("Missing env vars: MONGO_URI and JWT_SECRET must both be set.");
  process.exit(1);
}

const app = express();
app.use(express.json());

/* =========================== CORS =========================== */
const allowed = FRONTEND_URL.split(",")
  .map((s) => s.trim().replace(/\/$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // no Origin (curl, server-to-server, Netlify proxy) or no list set = allow
      const ok = !origin || allowed.length === 0 || allowed.includes(origin);
      if (!ok) console.warn(`CORS blocked "${origin}". Add it to FRONTEND_URL.`);
      cb(null, ok);
    },
  })
);

// wraps async routes so any error is returned as JSON instead of an empty response
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get("/", (_req, res) => res.json({ ok: true, service: "token-tracker-server" }));
app.get("/api/health", (_req, res) =>
  res.json({ ok: true, db: mongoose.connection.readyState === 1 ? "connected" : "disconnected" })
);

/* =========================== AUTH =========================== */
const makeToken = (user) => jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
const publicUser = (u) => ({ id: u._id, name: u.name, email: u.email });

app.post("/api/auth/register", wrap(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: "Name, email and password are required" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });

  const cleanEmail = email.toLowerCase().trim();
  const exists = await User.findOne({ email: cleanEmail });
  if (exists) return res.status(400).json({ error: "An account with this email already exists" });

  const user = await User.create({
    name: name.trim(),
    email: cleanEmail,
    passwordHash: await bcrypt.hash(password, 10),
  });
  res.status(201).json({ token: makeToken(user), user: publicUser(user) });
}));

app.post("/api/auth/login", wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Invalid email or password" });

  res.json({ token: makeToken(user), user: publicUser(user) });
}));

// protect everything below
const auth = wrap(async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in" });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: "Session expired, please log in again" });
  }
  const user = await User.findById(payload.id);
  if (!user) return res.status(401).json({ error: "Please log in" });
  req.user = user;
  next();
});

app.get("/api/auth/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

/* =========================== HELPERS =========================== */
async function stockByProduct(userId) {
  const match = { $match: { user: new mongoose.Types.ObjectId(userId) } };
  const [bought, sold] = await Promise.all([
    Purchase.aggregate([match, { $group: { _id: "$product", qty: { $sum: "$quantity" }, cost: { $sum: "$amount" } } }]),
    Sale.aggregate([match, { $group: { _id: "$product", qty: { $sum: "$quantity" }, revenue: { $sum: "$amount" } } }]),
  ]);
  return PRODUCTS.map((p) => {
    const b = bought.find((x) => x._id === p) || { qty: 0, cost: 0 };
    const s = sold.find((x) => x._id === p) || { qty: 0, revenue: 0 };
    return {
      product: p,
      boughtQty: b.qty,
      soldQty: s.qty,
      inStock: b.qty - s.qty,
      stockCost: b.cost,
      sales: s.revenue,
    };
  });
}

function readEntry(body, priceField) {
  const quantity = Number(body.quantity);
  const price = Number(body[priceField]);
  if (!body.date || Number.isNaN(new Date(body.date).getTime())) return { error: "Enter a valid date" };
  if (!Number.isInteger(quantity) || quantity < 1) return { error: "Quantity must be at least 1" };
  if (!PRODUCTS.includes(body.product)) return { error: "Select a valid token / product" };
  if (body[priceField] === "" || body[priceField] == null || !(price >= 0))
    return { error: "Enter a valid price" };
  return { quantity, price, amount: quantity * price };
}

const badId = (id) => !mongoose.isValidObjectId(id);

/* =========================== SALES =========================== */
app.get("/api/sales", auth, wrap(async (req, res) => {
  res.json(await Sale.find({ user: req.user._id }).sort({ date: -1, createdAt: -1 }));
}));

app.post("/api/sales", auth, wrap(async (req, res) => {
  const body = req.body || {};
  const e = readEntry(body, "sellingPrice");
  if (e.error) return res.status(400).json({ error: e.error });

  const stock = (await stockByProduct(req.user._id)).find((s) => s.product === body.product);
  if (e.quantity > stock.inStock)
    return res.status(400).json({ error: `Only ${stock.inStock} × ${body.product} in stock` });

  const sale = await Sale.create({
    user: req.user._id,
    date: body.date,
    quantity: e.quantity,
    product: body.product,
    sellingPrice: e.price,
    customerName: (body.customerName || "").trim(),
    amount: e.amount,
  });
  res.status(201).json(sale);
}));

app.delete("/api/sales/:id", auth, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "Sale not found" });
  await Sale.deleteOne({ _id: req.params.id, user: req.user._id });
  res.json({ ok: true });
}));

/* =========================== STOCK PURCHASES =========================== */
app.get("/api/purchases", auth, wrap(async (req, res) => {
  res.json(await Purchase.find({ user: req.user._id }).sort({ date: -1, createdAt: -1 }));
}));

app.post("/api/purchases", auth, wrap(async (req, res) => {
  const body = req.body || {};
  const e = readEntry(body, "costPrice");
  if (e.error) return res.status(400).json({ error: e.error });

  const purchase = await Purchase.create({
    user: req.user._id,
    date: body.date,
    quantity: e.quantity,
    product: body.product,
    costPrice: e.price,
    supplierName: (body.supplierName || "").trim(),
    amount: e.amount,
  });
  res.status(201).json(purchase);
}));

app.delete("/api/purchases/:id", auth, wrap(async (req, res) => {
  if (badId(req.params.id)) return res.status(404).json({ error: "Purchase not found" });
  const p = await Purchase.findOne({ _id: req.params.id, user: req.user._id });
  if (!p) return res.json({ ok: true });

  const stock = (await stockByProduct(req.user._id)).find((s) => s.product === p.product);
  if (stock.inStock - p.quantity < 0)
    return res.status(400).json({ error: "Can't delete: some of these tokens are already sold" });

  await p.deleteOne();
  res.json({ ok: true });
}));

/* =========================== SUMMARY =========================== */
app.get("/api/summary", auth, wrap(async (req, res) => {
  const products = await stockByProduct(req.user._id);
  const sum = (k) => products.reduce((a, p) => a + p[k], 0);
  const totalSales = sum("sales");
  const stockCost = sum("stockCost");
  res.json({
    totalSales,
    soldQty: sum("soldQty"),
    stockCost,
    boughtQty: sum("boughtQty"),
    profit: totalSales - stockCost, // sales minus stock cost
    tokensInStock: sum("inStock"),
    products,
  });
}));

app.get("/api/products", (_req, res) => res.json(PRODUCTS));

/* =========================== ERRORS =========================== */
app.use("/api", (_req, res) => res.status(404).json({ error: "API route not found" }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Server error" });
});

/* =========================== START =========================== */
console.log("Allowed frontend origins:", allowed.length ? allowed.join(", ") : "ALL");

mongoose
  .connect(MONGO_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => console.log(`API running on port ${PORT}`));
  })
  .catch((err) => {
    console.error(
      "MongoDB connection error:", err.message,
      "\n→ Check MONGO_URI (user/password) and Atlas → Network Access (allow 0.0.0.0/0)."
    );
    process.exit(1);
  });
