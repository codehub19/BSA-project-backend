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
        const response = await axios.post("https://iitdoauth.vercel.app/api/auth/resource", {
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            auth_code: code,
            state,
            grant_type: "authorization_code",
        });

        if (response.status === 200) {
            const token = jwt.sign(
                { user: response.data.user },
                process.env.APP_SECRET,
                { expiresIn: "1h" }
            );

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

            res.setHeader("Access-Control-Allow-Origin", "https://bsa-project-ivory.vercel.app/");
            res.setHeader("Access-Control-Allow-Credentials", "true");

            return res.redirect("https://bsa-project-ivory.vercel.app/"); 
        } else {
            console.error("Error during authentication:", response.data.message);
            return res.status(response.status).json({ message: "Error during authentication." });
        }
    } catch (err) {
        console.error("Error during OAuth callback:", err.message || err);
        return res.status(500).json({ message: "Internal Server Error." });
    }
}
