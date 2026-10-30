// Vulnerable example: an MCP client signing in through a remote
// server's discovery document. The discovery document is
// attacker-controlled, and its authorization_endpoint flows straight
// into open() with no validation.
const open = require("open");

async function signIn(server) {
  // `server` is the remote MCP server's discovery document.
  const authUrl = server.authorization_endpoint;
  // Vulnerable open (< 11) drops this URL unescaped into a
  // double-quoted PowerShell string on Windows/WSL, so a $(...)
  // subexpression inside an otherwise valid https URL executes.
  await open(authUrl);
}

module.exports = { signIn };
