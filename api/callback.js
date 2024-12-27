import axios from "axios";
import jwt from "jsonwebtoken";
import cookie from "cookie";
import dotenv from "dotenv";

dotenv.config();

export default async function handler(req, res) {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://bsa-project-ivory.vercel.app"
  );
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method !== "GET") {
    return res.status(405).json({ message: "Method not allowed" });
  }

  const { code, state } = req.query;

  if (!code || !state) {
    return res
      .status(400)
      .json({ message: "Missing code or state in the request." });
  }

  try {
    const response = await axios.post(
      "https://iitdoauth.vercel.app/api/auth/resource",
      {
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        auth_code: code,
        state,
        grant_type: "authorization_code",
      }
    );

    if (response.status === 200) {
      const token = jwt.sign(
        { user: response.data.user },
        process.env.APP_SECRET,
        { expiresIn: "1h" }
      );
      res.cookie("token", token, {
        httpOnly: true, // Prevent client-side JS access
        secure: true, // Send only over HTTPS
        maxAge: 3600000, // 1 hour
        sameSite: "None", // Required for cross-domain cookies
        path: "/", // Cookie is valid for the entire domain
      });

      return res.redirect(process.env.REDIRECT_URL);
    } else {
      console.error("Error during authentication:", response.data.message);
      return res
        .status(response.status)
        .json({ message: "Error during authentication." });
    }
  } catch (err) {
    console.error("Error during OAuth callback:", err.message || err);
    return res.status(500).json({ message: "Internal Server Error." });
  }
}
