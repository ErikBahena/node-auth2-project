const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const { findBy } = require("../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) return next({ status: 401, message: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next({ status: 401, message: "Token invalid" });

    req.decodedJwt = decoded;
    next();
  });
};

const only = (role_name) => (req, res, next) => {
  const decoded = req.decodedJwt;

  if (decoded.role_name !== role_name)
    return next({ status: 403, message: "This is not for you" });

  next();
};

const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;

  const user = await findBy("u.username", username);

  if (!user) return next({ status: 401, message: "Invalid credentials" });

  req.user = user;
  next();
};

const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;

  if (!role_name || role_name.trim() === "") {
    req.body.role_name = "student";
    return next();
  }

  if (role_name.trim() === "admin")
    return next({ status: 422, message: "Role name can not be admin" });

  if (role_name.trim().length > 32)
    return next({
      status: 422,
      message: "Role name can not be longer than 32 chars",
    });

  req.body.role_name = role_name.trim();
  next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
