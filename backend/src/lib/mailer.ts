import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export const sendOtpEmail = async ({
  to,
  code,
}: {
  to: string;
  code: string;
}) => {
  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: "Your verification code",
    text: `Your code is ${code}. It expires in 10 minutes.`,
  });
};
