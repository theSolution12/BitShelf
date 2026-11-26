import pino from "pino";

const isDevelopment = process.env.NODE_ENV !== "production";

const logger = pino<"success">({
  level: process.env.LOG_LEVEL || "info",

  customLevels: {
    success: 35,
  },

  ...(isDevelopment && {
    transport: {
      target: "pino-pretty",
      options: {
        colorize: true,
        translateTime: "SYS:standard",
        ignore: "pid,hostname",
      },
    },
  }),

  timestamp: pino.stdTimeFunctions.isoTime,

  redact: [
    "password",
    "passwordHash",
    "token",
    "tokenHash",
    "req.headers.authorization",
    "req.headers.cookie",
  ],
});

export default logger;
