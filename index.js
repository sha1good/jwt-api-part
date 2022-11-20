const { response } = require("express");
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cors = require("cors");
app.use(cors());
app.use(express.json());

const users = [
  {
    id: "1",
    username: "sheriff",
    password: "Password123@",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

let refreshTokens = [];
app.post("/api/refresh", (request, response) => {
  const refreshToken = request.body.token;
  if (!refreshToken)
    return response.status(401).json("You are not authenticated!");
  if (!refreshTokens.includes(refreshToken)) {
    return response.status(403).json("RefreshToken not valid!");
  }
  jwt.verify(refreshToken, "myRefreshToken", (error, user) => {
    error && console.log(error);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);
    response.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
    expiresIn: "1m",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshToken");
};

app.post("/api/login", (request, response) => {
  const { username, password } = request.body;
  const user = users.find((user) => {
    return user.username === username && user.password === password;
  });
  if (user) {
    //Generating your access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);
    response.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    response.status(400).json("Username or password incorrect!");
  }
});

const verify = (request, response, next) => {
  const authHeaders = request.headers.authorization;
  if (authHeaders) {
    const token = authHeaders.split(" ")[1];
    jwt.verify(token, "mySecretKey", (error, user) => {
      if (error) {
        response.status(403).json("Token not valid!");
      }
      request.user = user;
      next();
    });
  } else {
    response.status(401).json("You are not authenticated!");
  }
};

app.delete("/api/users/:userId", verify, (request, response) => {
  if (request.user.id === request.params.userId || request.user.isAdmin) {
    response.status(200).json("User has been deleted!");
  } else {
    response.status(403).json("You are not allowed to delete this user");
  }
});

app.post("/api/logout", verify, (request, response) => {
    const refreshToken = request.body.token;
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    response.status(200).json("You have successfully logged out!");
  });

app.listen(process.env.PORT || 5000, () => console.log("Backend server is running!"));
