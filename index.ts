import nodemailer from "nodemailer";

interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
  ignoreTLS?: boolean;
  tls?: {
    rejectUnauthorized: boolean;
  };
}

async function sendTestEmail() {
  const config: EmailConfig = {
    // host: "localhost", // Change to your server's IP/domain for production
    host: "13.127.138.214", // <<< CHANGE THIS
    port: 2525,

    secure: false,
    auth: {
      user: "admin@snehaa.store",
      pass: "your_secure_password_here", // Match your Docker environment
    },
    // For testing without TLS
    ignoreTLS: true,
    tls: {
      rejectUnauthorized: false,
    },
  };

  const transporter = nodemailer.createTransport(config);

  try {
    const info = await transporter.sendMail({
      from: '"Test Sender" <sender@snehaa.store>',
      to: "santoshdahal1981@gmail.com", // Replace with your actual email
      subject: "Test Email from Custom SMTP Server",
      text: "Hello! This is a test email from your custom Go SMTP server.",
      html: `
        <h2>Test Email</h2>
        <p>Hello! This is a test email from your custom Go SMTP server.</p>
        <p>Server: <strong>snehaa.store</strong></p>
        <p>Time: <strong>${new Date().toISOString()}</strong></p>
      `,
    });

    console.log("✅ Message sent successfully!");
    console.log("Message ID:", info.messageId);
    console.log("Response:", info.response);
  } catch (error) {
    console.error("❌ Error sending email:", error);
  }
}

// Run the test
sendTestEmail();
