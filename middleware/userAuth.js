import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res.json({ success: false, message: "Unauthorized" });
  }

  try {
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

    if (tokenDecode.id) {
      req.user = { userId: tokenDecode.id }; //  attach user info safely
    } else {
      return res.json({ success: false, message: "Unauthorized" });
    }

    next();
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};


export default userAuth;