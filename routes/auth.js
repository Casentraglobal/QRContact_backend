import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import appleSigninAuth from "apple-signin-auth";
import axios from "axios";
import User from "../models/User.js";
import { auth } from "../middleware/auth.js";

const router = express.Router();

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const FRONTEND_URL = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");

// Helper: create app JWT
const createJwt = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
};

// ---------------------- Local register ----------------------
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields required" });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "Email already in use" });

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      provider: "local",
    });

    const token = createJwt(user);

    res.status(201).json({
      message: "Registered",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------------- Local login ----------------------
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "All fields required" });

    const user = await User.findOne({ email });
    if (!user || !user.password)
      return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = createJwt(user);

    res.json({
      message: "Login success",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------------- Google login ----------------------
router.post("/google", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ message: "No token" });

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub, email, name } = payload;

    if (!email) {
      return res.status(400).json({ message: "Google email missing" });
    }

    let user = await User.findOne({ provider: "google", providerId: sub });

    if (!user) {
      user = await User.findOne({ email });

      if (user) {
        user.provider = "google";
        user.providerId = sub;
        await user.save();
      } else {
        user = await User.create({
          name: name || email.split("@")[0],
          email,
          provider: "google",
          providerId: sub,
        });
      }
    }

    const token = createJwt(user);

    res.json({
      message: "Google login success",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    console.error("Google login error:", err);
    res.status(401).json({ message: "Google token invalid" });
  }
});

// ---------------------- Apple login ----------------------
// Will NOT work unless you have paid Apple Dev + proper env values.
router.post("/apple", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ message: "No token" });

    const payload = await appleSigninAuth.verifyIdToken(idToken, {
      audience: process.env.APPLE_CLIENT_ID,
      ignoreExpiration: false,
    });

    const { sub, email } = payload;

    let finalEmail = email;
    if (!finalEmail) {
      finalEmail = `apple_${sub}@noemail.apple`;
    }

    let user = await User.findOne({ provider: "apple", providerId: sub });

    if (!user) {
      user = await User.findOne({ email: finalEmail });

      if (user) {
        user.provider = "apple";
        user.providerId = sub;
        await user.save();
      } else {
        user = await User.create({
          name: finalEmail.split("@")[0],
          email: finalEmail,
          provider: "apple",
          providerId: sub,
        });
      }
    }

    const token = createJwt(user);

    res.json({
      message: "Apple login success",
      user: { id: user._id, name: user.name, email: user.email },
      token,
    });
  } catch (err) {
    console.error("Apple login error:", err);
    res.status(401).json({ message: "Apple token invalid" });
  }
});

// ---------------------- SSO (generic OIDC-style skeleton) ----------------------
// Step 1: redirect to IdP
router.get("/sso/redirect", (req, res) => {
  const { SSO_AUTH_URL, SSO_CLIENT_ID, SSO_REDIRECT_URI } = process.env;

  if (!SSO_AUTH_URL || !SSO_CLIENT_ID || !SSO_REDIRECT_URI) {
    console.error("SSO redirect misconfigured:", {
      SSO_AUTH_URL,
      SSO_CLIENT_ID,
      SSO_REDIRECT_URI,
    });
    return res.status(500).send("SSO not configured");
  }

  let authUrl;
  try {
    authUrl = new URL(SSO_AUTH_URL);
  } catch (e) {
    console.error("Invalid SSO_AUTH_URL:", SSO_AUTH_URL);
    return res.status(500).send("SSO URL invalid");
  }

  authUrl.searchParams.set("client_id", SSO_CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", SSO_REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid email profile");

  res.redirect(authUrl.toString());
});

// Step 2: callback from IdP
router.get("/sso/callback", async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send("Missing code");

    const {
      SSO_TOKEN_URL,
      SSO_REDIRECT_URI,
      SSO_CLIENT_ID,
      SSO_CLIENT_SECRET,
    } = process.env;

    if (!SSO_TOKEN_URL || !SSO_REDIRECT_URI || !SSO_CLIENT_ID || !SSO_CLIENT_SECRET) {
      console.error("SSO callback misconfigured:", {
        SSO_TOKEN_URL,
        SSO_REDIRECT_URI,
        SSO_CLIENT_ID,
        SSO_CLIENT_SECRET,
      });
      return res.status(500).send("SSO not configured");
    }

    // Exchange code for tokens
    const tokenRes = await axios.post(
      SSO_TOKEN_URL,
      new URLSearchParams({
        grant_type: "authorization_code",
        code: code.toString(),
        redirect_uri: SSO_REDIRECT_URI,
        client_id: SSO_CLIENT_ID,
        client_secret: SSO_CLIENT_SECRET,
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { id_token } = tokenRes.data;
    if (!id_token) {
      console.error("SSO: no id_token from IdP response:", tokenRes.data);
      return res.status(400).send("No id_token from IdP");
    }

    // WARNING: decode only; for real use, verify with IdP's JWKS
    const decoded = jwt.decode(id_token) || {};
    const sub = decoded.sub;
    const email = decoded.email;

    if (!sub && !email) {
      console.error("SSO: decoded id_token has no sub/email:", decoded);
      return res.status(400).send("Invalid id_token from IdP");
    }

    let user = null;

    if (sub) {
      user = await User.findOne({ provider: "sso", providerId: sub });
    }

    if (!user && email) {
      user = await User.findOne({ email });
    }

    if (!user) {
      const finalEmail = email || `sso_${sub}@noemail.sso`;
      user = await User.create({
        name: finalEmail.split("@")[0],
        email: finalEmail,
        provider: "sso",
        providerId: sub || finalEmail, // fallback
      });
    } else {
      // Ensure provider fields are set
      if (!user.provider) user.provider = "sso";
      if (!user.providerId && sub) user.providerId = sub;
      await user.save();
    }

    const appToken = createJwt(user);

    const redirectUrl = `${FRONTEND_URL}/sso-success?token=${appToken}`;
    console.log("SSO callback redirecting to:", redirectUrl);

    res.redirect(redirectUrl);
  } catch (err) {
    console.error("SSO callback error:", err);
    res.status(500).send("SSO error");
  }
});

// ---------------------- Protected test route ----------------------
router.get("/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json({ user });
  } catch (err) {
    console.error("Me route error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
