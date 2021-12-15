const bcrypt = require("bcryptjs");
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { BCRYPT_ROUNDS } = require("../config"); // use this secret!
const { tokenBuilder } = require("../auth/auth-helpers");

const User = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const user = req.body;

  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);

  user.password = hash;

  User.add(user)
    .then((newUser) => res.status(201).json(newUser))
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { password } = req.body;

  const userFromDb = req.user;

  if (bcrypt.compareSync(password, userFromDb.password)) {
    const token = tokenBuilder(userFromDb);

    res.status(200).json({
      message: `${userFromDb.username} is back!`,
      token,
    });
  } else next({ status: 401, message: "Invalid Credentials" });
});

module.exports = router;
