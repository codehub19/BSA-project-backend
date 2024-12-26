import express from 'express';
import axios from 'axios';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cookieParser());

app.get("/callback", async (req, res) => {
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
            res.cookie("token", token);
            return res.redirect("http://localhost:5173/"); 
        } else {
            console.error("Error during authentication:", response.data.message);
            return res.status(response.status).json({ message: "Error during authentication." });
        }
    } catch (err) {
        console.error("Error during OAuth callback:", err.message || err);
        return res.status(500).json({ message: "Internal Server Error." });
    }
});


const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
