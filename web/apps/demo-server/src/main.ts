import { loadConfig } from "./config.js";
import { buildServer } from "./server.js";

const config = loadConfig();
const server = await buildServer(config);
await server.listen({ host: config.host, port: config.port });
