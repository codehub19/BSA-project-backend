import axios from "axios";
import jwt from "jsonwebtoken";
import cookie from "cookie";

export default async function callback(req, res) {
    if (req.method !== "GET") {
        return res.status(405).json({ message: "Method not allowed" });
    }

    const { code, state } = req.query;

    if (!code || !state) {
        return res.status(400).json({ message: "Missing code or state in the request." });
    }

    try {
        // Exchange the auth code for a token
        const response = await axios.post("https://iitdoauth.vercel.app/api/auth/resource", {
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            auth_code: code,
            state,
            grant_type: "authorization_code",
        });

        if (response.status === 200) {
            // Create a signed JWT token
            const token = jwt.sign(
                { user: response.data.user },
                process.env.APP_SECRET,
                { expiresIn: "1h" }
            );

            // Set the cookie with proper attributes for cross-origin requests
            res.setHeader(
                "Set-Cookie",
                cookie.serialize("token", token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production", // Use HTTPS in production
                    sameSite: "None", // Required for cross-origin cookies
                    path: "/", // Available throughout the site
                    maxAge: 3600, // Cookie valid for 1 hour
                })
            );

            // Allow the frontend to receive the cookie
            res.setHeader("Access-Control-Allow-Origin", "https://your-frontend.vercel.app"); // Replace with your frontend domain
            res.setHeader("Access-Control-Allow-Credentials", "true");

            // Redirect the user back to the frontend
            return res.redirect("https://your-frontend.vercel.app"); // Replace with your frontend URL
        } else {
            console.error("Error during authentication:", response.data.message);
            return res.status(response.status).json({ message: "Error during authentication." });
        }
    } catch (err) {
        console.error("Error during OAuth callback:", err.message || err);
        return res.status(500).json({ message: "Internal Server Error." });
    }
}
