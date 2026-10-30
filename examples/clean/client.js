// Clean example: the same shape as examples/vulnerable, but the URL
// is allowlisted to https and encoded before it reaches open(), and
// the project pins a fixed open version (see package.json).
const open = require("open");

async function signIn(server) {
  const authUrl = server.authorization_endpoint;
  if (!authUrl.startsWith("https://")) {
    throw new Error("refusing non-https authorization endpoint");
  }
  const safeUrl = encodeURIComponent(authUrl);
  await open(safeUrl);
}

module.exports = { signIn };
