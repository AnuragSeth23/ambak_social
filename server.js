require("dotenv").config({ quiet: true });
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const db = require("./db");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

// If a request has no JSON body, use an empty object (so destructuring never crashes)
app.use((req, res, next) => {
  if (!req.body) {
    req.body = {};
  }
  next();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

const otpStore = {};

const resetStore = {};

// OTP limits
const OTP_RESEND_WAIT = 60 * 1000;   // 60 seconds before a new OTP can be requested
const OTP_MAX_ATTEMPTS = 3;          // wrong tries allowed per OTP
// ---------------- IMAGE UPLOAD ----------------

// Folder for images (create it if it is missing)
const uploadFolder = path.join(__dirname, "uploads");
fs.mkdirSync(uploadFolder, { recursive: true });

// Where and with what name to save the uploaded image
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadFolder);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + ext);
  },
});

// Allow only images, max 5 MB
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = [".jpg", ".jpeg", ".png", ".gif", ".webp"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext) && file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only JPG, PNG, GIF or WEBP images are allowed"));
    }
  },
});

// Run multer and send a clean 400 if the file is wrong
function uploadImage(req, res, next) {
  upload.single("image")(req, res, (error) => {
    if (error) {
      let message = error.message;
      if (error.code === "LIMIT_FILE_SIZE") {
        message = "Image must be smaller than 5 MB";
      }
      return res.status(400).json({ message: message });
    }
    next();
  });
}

// Show uploaded images: /uploads/abc.jpg
app.use("/uploads", express.static(uploadFolder));

// Middleware: allow only logged-in users
function checkLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Please login first" });
  }
  next();
}


// ---------------- VALIDATION ----------------

// Check password rules, return error text or null
function checkPassword(password) {
  if (!password || password.length < 8) {
    return "Password must be at least 8 characters";
  }
  if (!/[A-Z]/.test(password)) {
    return "Password must have at least one capital letter";
  }
  if (!/[0-9]/.test(password)) {
    return "Password must have at least one number";
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return "Password must have at least one special character";
  }
  return null;
}

function validateSignup(name, username, mobile, email, password, verifyBy) {
  if (!name || name.trim() === "") {
    return { field: "name", message: "Full name is required" };
  }
  if (!username) {
    return { field: "username", message: "Username is required" };
  }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return { field: "username", message: "Username must be 3-20 characters: letters, numbers or _" };
  }
  if (!mobile) {
    return { field: "mobile", message: "Mobile number is required" };
  }
  if (!/^[6-9][0-9]{9}$/.test(mobile)) {
    return { field: "mobile", message: "Mobile must be 10 digits and start with 6, 7, 8 or 9" };
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { field: "email", message: "Please enter a valid email" };
  }
  if (verifyBy === "email" && !email) {
    return { field: "email", message: "Email is required to verify via email" };
  }
  const passwordError = checkPassword(password);
  if (passwordError) {
    return { field: "password", message: passwordError };
  }
  return null;
}

// ---------------- PAGE ----------------

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});
//---------------- SIGNUP STEP 1: SEND OTP ----------------

app.post("/send-otp", async (req, res) => {
  try {
    const { name, username, email, mobile, password, verifyBy } = req.body;

    // 1. Validate all fields
    const validationError = validateSignup(name, username, mobile, email, password, verifyBy);
    if (validationError) {
      return res.status(400).json(validationError);
    }

    // OTP resend limit: wait 60 seconds before asking again
    const existingOtp = otpStore[mobile];
    if (existingOtp && Date.now() - existingOtp.sentAt < OTP_RESEND_WAIT) {
      return res.status(429).json({ message: "Please wait 60 seconds before requesting a new OTP" });
    }

    // 2. Check duplicates (one by one, so we know which field)
    const [usernameExists] = await db.query("SELECT id FROM users WHERE username = ?", [username]);
    if (usernameExists.length > 0) {
      return res.status(400).json({ field: "username", message: "Username already exists" });
    }
    const [mobileExists] = await db.query("SELECT id FROM users WHERE mobile = ?", [mobile]);
    if (mobileExists.length > 0) {
      return res.status(400).json({ field: "mobile", message: "Mobile number is already registered" });
    }

    if (email) {
      const [emailExists] = await db.query("SELECT id FROM users WHERE email = ?", [email]);
      if (emailExists.length > 0) {
        return res.status(400).json({ field: "email", message: "Email is already registered" });
      }
    }

    // 3. Create OTP and keep user data until verified
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    otpStore[mobile] = {
      otp: otp,
      sentAt: Date.now(),
      attempts: 0,
      expiresAt: Date.now() + 5 * 60 * 1000,
      user: {
        name: name.trim(),
        username: username,
        email: email || null,
        mobile: mobile,
        password: hashedPassword,
      },
    };
     
    let sentTo = mobile;
    if (verifyBy === "email") {
      sentTo = email;
    }

    // In production, send SMS / email here instead of printing
    console.log("OTP for " + sentTo + " : " + otp);

    res.json({ message: "OTP sent to: " + sentTo });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- SIGNUP STEP 2: VERIFY OTP ----------------

app.post("/verify-otp", async (req, res) => {
  try {
    const { mobile, otp } = req.body;

    const record = otpStore[mobile];

    if (!record) {
      return res.status(400).json({ field: "otp", message: "Please request an OTP first" });
    }

    if (Date.now() > record.expiresAt) {
      delete otpStore[mobile];
      return res.status(400).json({ field: "otp", message: "OTP has expired, please request a new one" });
    }

    // Wrong OTP: count attempts, block after 3
    if (record.otp !== otp) {
      record.attempts = record.attempts + 1;
      if (record.attempts >= OTP_MAX_ATTEMPTS) {
        delete otpStore[mobile];
        return res.status(429).json({ field: "otp", message: "Too many wrong attempts, please request a new OTP" });
      }
      const left = OTP_MAX_ATTEMPTS - record.attempts;
      return res.status(400).json({ field: "otp", message: "Invalid OTP. " + left + " attempts left" });
    }

    const user = record.user;

    await db.query(
      "INSERT INTO users (name, username, email, mobile, password) VALUES (?, ?, ?, ?, ?)",
      [user.name, user.username, user.email, user.mobile, user.password]
    );

    delete otpStore[mobile];

    res.status(201).json({ message: "Account created successfully! Please log in." });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- LOGIN ----------------

app.post("/login", async (req, res) => {
  try {
    const { loginId, password } = req.body;

    if (!loginId) {
      return res.status(400).json({ field: "loginId", message: "Username, mobile or email is required" });
    }
    if (!password) {
      return res.status(400).json({ field: "loginPassword", message: "Password is required" });
    }

    const [users] = await db.query(
      "SELECT id, username, password FROM users WHERE username = ? OR mobile = ? OR email = ?",
      [loginId, loginId, loginId]
    );
    if (users.length === 0) {
      return res.status(401).json({ message: "Invalid login credentials" });
    }

    const user = users[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid login credentials" });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
   
    res.json({ message: "Login successful", username: user.username });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});
 
// ---------------- FORGOT PASSWORD STEP 1: SEND OTP ----------------

app.post("/forgot-password", async (req, res) => {
  try {
    const { loginId } = req.body;

       if (!loginId) {
      return res.status(400).json({ field: "resetId", message: "Mobile number or email is required" });
    }

    const isMobile = /^[6-9][0-9]{9}$/.test(loginId);
    const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(loginId);
    if (!isMobile && !isEmail) {
      return res.status(400).json({ field: "resetId", message: "Please enter a valid mobile number or email" });
    }

    const [users] = await db.query(
      "SELECT id, mobile FROM users WHERE mobile = ? OR email = ?",
      [loginId, loginId]
    );
  
    // OTP resend limit: wait 60 seconds before asking again
    const existingReset = resetStore[loginId];
    if (existingReset && Date.now() - existingReset.sentAt < OTP_RESEND_WAIT) {
      return res.status(429).json({ message: "Please wait 60 seconds before requesting a new OTP" });
    }

    if (users.length > 0) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      resetStore[loginId] = {
        otp: otp,
        sentAt: Date.now(),
        attempts: 0,
        userId: users[0].id,
        expiresAt: Date.now() + 5 * 60 * 1000,
      };

      // In production, send SMS / email here instead of printing
      console.log("Password reset OTP for " + users[0].mobile + " : " + otp);
    }

    // Same message whether the account exists or not (security)
    res.json({ message: "If this account exists, an OTP has been sent" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- FORGOT PASSWORD STEP 2: RESET ----------------

app.post("/reset-password", async (req, res) => {
  try {
    const { loginId, otp, newPassword } = req.body;

    const passwordError = checkPassword(newPassword);
    if (passwordError) {
      return res.status(400).json({ field: "newPassword", message: passwordError });
    }

    const record = resetStore[loginId];

    if (!record) {
      return res.status(400).json({ field: "resetOtp", message: "Invalid OTP" });
    }

    if (Date.now() > record.expiresAt) {
      delete resetStore[loginId];
      return res.status(400).json({ field: "resetOtp", message: "OTP has expired, please request a new one" });
    }

    // Wrong OTP: count attempts, block after 3
    if (record.otp !== otp) {
      record.attempts = record.attempts + 1;
      if (record.attempts >= OTP_MAX_ATTEMPTS) {
        delete resetStore[loginId];
        return res.status(429).json({ field: "resetOtp", message: "Too many wrong attempts, please request a new OTP" });
      }
      const left = OTP_MAX_ATTEMPTS - record.attempts;
      return res.status(400).json({ field: "resetOtp", message: "Invalid OTP. " + left + " attempts left" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await db.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, record.userId]);

    delete resetStore[loginId];

    res.json({ message: "Password changed successfully! Please log in." });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Who is logged in?
app.get("/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Not logged in" });
  }
  res.json({ username: req.session.username });
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logged out successfully" });
});

// ---------------- POSTS ----------------

// Get posts 10 at a time (newest first) with likes, shares and comments
// First page:  GET /posts
// Next pages:  GET /posts?before=155   (posts older than id 155)
const POSTS_PER_PAGE = 10;

app.get("/posts", checkLogin, async (req, res) => {
  try {
    // "before" = id of the last post the user already has (0 = start from newest)
    const before = Number(req.query.before) || 0;

    let where = "";
    const values = [req.session.userId];
    if (before > 0) {
      where = "WHERE posts.id < ?";
      values.push(before);
    }
    values.push(POSTS_PER_PAGE + 1); // ask for 1 extra to know if more posts exist

    const [posts] = await db.query(
      `SELECT posts.id, posts.content, posts.image, posts.created_at, users.username,
        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS like_count,
        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id AND likes.user_id = ?) AS liked_by_me,
        (SELECT COUNT(*) FROM shares WHERE shares.post_id = posts.id) AS share_count
       FROM posts
       JOIN users ON posts.user_id = users.id
       ${where}
       ORDER BY posts.id DESC
       LIMIT ?`,
      values
    );

    // Got the extra one? Then there is a next page. Remove the extra post.
    const hasMore = posts.length > POSTS_PER_PAGE;
    if (hasMore) {
      posts.pop();
    }

    // Comments only for THESE posts (not every comment in the database)
    if (posts.length > 0) {
      const ids = posts.map((post) => post.id);
      const [comments] = await db.query(
        `SELECT comments.post_id, comments.comment_text, users.username
         FROM comments
         JOIN users ON comments.user_id = users.id
         WHERE comments.post_id IN (?)
         ORDER BY comments.id`,
        [ids]
      );
      for (const post of posts) {
        post.comments = comments.filter((c) => c.post_id === post.id);
      }
    }

    res.json({
      posts: posts,
      hasMore: hasMore,
      nextBefore: posts.length > 0 ? posts[posts.length - 1].id : null,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Create a new post
app.post("/posts", checkLogin, uploadImage, async (req, res) => {
  try {
    const content = (req.body.content || "").trim();

    // Image saved by multer? Then keep its web path, e.g. /uploads/1732...jpg
    let image = null;
    if (req.file) {
      image = "/uploads/" + req.file.filename;
    }

    // Need text OR image (or both)
    if (content === "" && !image) {
      return res.status(400).json({ message: "Write something or add an image" });
    }

    const [result] = await db.query("INSERT INTO posts (user_id, content, image) VALUES (?, ?, ?)", [
      req.session.userId,
      content,
      image,
    ]);

    // Read back the new post (with author name and time) to send in the response
    const [rows] = await db.query(
      `SELECT posts.id, posts.content, posts.image, posts.created_at, users.username
       FROM posts
       JOIN users ON posts.user_id = users.id
       WHERE posts.id = ?`,
      [result.insertId]
    );

    const post = rows[0];
    post.like_count = 0;
    post.liked_by_me = 0;
    post.share_count = 0;
    post.comments = [];

    console.log(req.session.username + " created post " + post.id);

    res.status(201).json({ message: "Post created successfully", post: post });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Like / Unlike (toggle)
app.post("/posts/:id/like", checkLogin, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.session.userId;
    const username = req.session.username;

    // Post exist karti hai?
    const [post] = await db.query("SELECT id FROM posts WHERE id = ?", [postId]);
    if (post.length === 0) {
      return res.status(404).json({ message: "Post not found" });
    }

    const [existing] = await db.query(
      "SELECT id FROM likes WHERE user_id = ? AND post_id = ?",
      [userId, postId]
    );

    // Toggle: already liked -> unlike, else -> like
    let liked;
    if (existing.length > 0) {
      await db.query("DELETE FROM likes WHERE user_id = ? AND post_id = ?", [userId, postId]);
      liked = false;
    } else {
      await db.query("INSERT INTO likes (user_id, post_id) VALUES (?, ?)", [userId, postId]);
      liked = true;
    }

    // Updated like count, so frontend does not need to reload all posts
    const [countRows] = await db.query(
      "SELECT COUNT(*) AS likeCount FROM likes WHERE post_id = ?",
      [postId]
    );

    console.log(username + (liked ? " liked" : " unliked") + " post " + postId);

    res.json({
      message: liked ? "Post liked" : "Post unliked",
      action: liked ? "like" : "unlike",
      liked: liked,
      postId: Number(postId),
      likedBy: username,
      likeCount: countRows[0].likeCount,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Share a post (WhatsApp, email, ...). Count = how many users shared it
app.post("/posts/:id/share", checkLogin, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.session.userId;

    // Where was it shared? Only known names, anything else = "other"
    const platforms = ["whatsapp", "email", "telegram", "x", "facebook", "copy", "other"];
    let via = "other";
    if (platforms.includes(req.body.platform)) {
      via = req.body.platform;
    }

    // Post exist karti hai?
    const [post] = await db.query("SELECT id FROM posts WHERE id = ?", [postId]);
    if (post.length === 0) {
      return res.status(404).json({ message: "Post not found" });
    }

    const [existing] = await db.query(
      "SELECT id FROM shares WHERE user_id = ? AND post_id = ?",
      [userId, postId]
    );
    // Same user shares again (e.g. WhatsApp, then email): no error, count stays same
    const alreadyShared = existing.length > 0;
    if (!alreadyShared) {
      await db.query("INSERT INTO shares (user_id, post_id) VALUES (?, ?)", [userId, postId]);
    }

    const [countRows] = await db.query(
      "SELECT COUNT(*) AS shareCount FROM shares WHERE post_id = ?",
      [postId]
    );

    console.log(req.session.username + " shared post " + postId + " via " + via);

    res.status(alreadyShared ? 200 : 201).json({
      message: "Post shared via " + via,
      postId: Number(postId),
      sharedBy: req.session.username,
      via: via,
      alreadyShared: alreadyShared,
      shareCount: countRows[0].shareCount,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});


// Add a comment
app.post("/posts/:id/comment", checkLogin, async (req, res) => {
  try {
    const postId = req.params.id;
    const { text } = req.body;

    if (!text || text.trim() === "") {
      return res.status(400).json({ message: "Comment cannot be empty" });
    }
    if (text.trim().length > 500) {
      return res.status(400).json({ message: "Comment can be at most 500 characters" });
    }

    // Post exist karti hai? Aur post kiski hai?
    const [post] = await db.query(
      `SELECT posts.id, users.username AS post_owner
       FROM posts
       JOIN users ON posts.user_id = users.id
       WHERE posts.id = ?`,
      [postId]
    );
    if (post.length === 0) {
      return res.status(404).json({ message: "Post not found" });
    }

    const [result] = await db.query(
      "INSERT INTO comments (user_id, post_id, comment_text) VALUES (?, ?, ?)",
      [req.session.userId, postId, text.trim()]
    );

    console.log(req.session.username + " commented on " + post[0].post_owner + "'s post " + postId);

    res.status(201).json({
      message: "Comment added successfully",
      comment: {
        id: result.insertId,
        postId: Number(postId),
        commentedBy: req.session.username,
        postOwner: post[0].post_owner,
        text: text.trim(),
      },
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Delete my post
app.delete("/posts/:id", checkLogin, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.session.userId;

    const [rows] =await db.query(
      `select posts.content, posts.image, posts.created_at,
      (select count(*) from likes where likes.post_id = posts.id) As likes,
      (select count(*) from comments where comments.post_id = posts.id ) As comments,
      (select count(*) from shares where shares.post_id = posts.id) As shares
      from posts
      where posts.id = ? and posts.user_id =?`,
      [postId, userId]
    );

    if (rows.length ===0 ) {
       return res.status(404).json({ message: "post not found"});

    }
    const post = rows[0];
    await db.query("delete from posts where id = ?", [postId]);
        let imageDeleted = false;
    if (post.image) {
      try {
        await fs.promises.unlink(path.join(__dirname, post.image));   // join
        imageDeleted = true;                                           // true
      } catch (error) {
        console.log("Could not delete image file:", error.message);
      }
    }

    res.json({
      message : "post deleted",
      imageDeleted: imageDeleted,
      postId: Number(postId),
      deletedBy: req.session.username,
      post:{content:post.content, image: post.image, createsAy: post.created_at},
      removed: { likes: post.likes, comments: post.comments, shares: post.shares},


    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

//------------------EDIT POSTS -----------------

// Edit my post (change its text)
app.put("/posts/:id", checkLogin, async (req, res) => {
  try {
    const postId = req.params.id;
    const userId = req.session.userId;
    const content = (req.body.content || "").trim();

    if (content === "") {
      return res.status(400).json({ message: "Post cannot be empty" });
    }

    // 1. Pehle purana text nikalo (sirf meri post)
    const [rows] = await db.query(
      "SELECT content FROM posts WHERE id = ? AND user_id = ?",
      [postId, userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: "Post not found" });
    }
    const oldContent = rows[0].content || "";

    // 2. Text same hai to DB update ki zarurat nahi
    if (oldContent === content) {
      return res.json({
        message: "No changes",
        postId: Number(postId),
        changed: false,
        content: content,
      });
    }

    // 3. Naya text save karo
    await db.query("UPDATE posts SET content = ? WHERE id = ?", [content, postId]);

    console.log(req.session.username + " edited post " + postId);

    // 4. Pehle kya tha, ab kya hai
    res.json({
      message: "Post updated",
      postId: Number(postId),
      changed: true,
      editedBy: req.session.username,
      editedAt: new Date(),
      before: oldContent,
      after: content,
      content: content,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});
// ---------------- SERVER START ----------------

app.listen(PORT, () => {
  console.log("Server started on port " + PORT);
});



