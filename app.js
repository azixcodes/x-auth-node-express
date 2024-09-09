import express from "express";
import session from "express-session";
import crypto from "crypto";
import cors from "cors";
import { TwitterApi } from "twitter-api-v2";
import cookieParser from "cookie-parser";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 8000;

// CORS setup
app.use(
  cors({
    origin: "http://localhost:3000", // Your client URL for CORS, adjust accordingly
    credentials: true,
  })
);

// Session setup
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // set true in production with HTTPS
  })
);

// Serve static files from 'public' directory
app.use(express.static(path.join(process.cwd(), "public")));

// Twitter API client setup
const twitterClient = new TwitterApi({
  clientId: process.env.TWITTER_CLIENT_ID,
  clientSecret: process.env.TWITTER_CLIENT_SECRET,
});

const callbackURL = process.env.TWITTER_REDIRECT_URI;

// Helper function to generate code verifier and code challenge
function generateCodeVerifier() {
  const randomBuffer = crypto.randomBytes(32);
  return randomBuffer.toString("hex");
}

function generateCodeChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier).digest("base64url");
}

// Step 1: Twitter login route (redirect to Twitter for OAuth)
app.get("/auth/twitter", (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  req.session.codeVerifier = codeVerifier;
  req.session.state = crypto.randomBytes(8).toString("hex");

  const { url } = twitterClient.generateOAuth2AuthLink(callbackURL, {
    scope: ["tweet.read", "users.read", "offline.access"],
    state: req.session.state,
    code_challenge: codeChallenge,
    code_challenge_method: "s256",
  });

  res.redirect(url);
});

// Step 2: Callback route from Twitter
app.get("/auth/twitter/callback", async (req, res) => {
  const { code, state } = req.query;

  if (state !== req.session.state) {
    return res.status(400).send("State mismatch!");
  }

  try {
    const {
      client: loggedClient,
      accessToken,
      refreshToken,
      expiresIn,
    } = await twitterClient.loginWithOAuth2({
      code,
      codeVerifier: req.session.codeVerifier,
      redirectUri: callbackURL,
    });

    req.session.accessToken = accessToken;
    req.session.refreshToken = refreshToken;
    req.session.expiresIn = expiresIn;

    console.log("Twitter login successful");
    // Redirect user to success page
    res.status(200).json({ message: "Login Success" });
  } catch (error) {
    console.error("Error logging in with Twitter:", error);
    res.status(500).send("Error during login", error.message);
  }
});

// Logout route to clear session and cookies
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("Logout failed");
    }

    res.clearCookie("connect.sid", { path: "/" });
    res.redirect("/"); // Redirect to homepage or login page after logout
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
