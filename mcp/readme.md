export MCP_TOKEN=$(openssl rand -hex 24)
echo $MCP_TOKEN   # save this, your MCP client will need it
node server.js