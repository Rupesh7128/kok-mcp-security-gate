import "./globals.css";

export const metadata = {
  title: "MCP Security Gate + BotShield — Kingdom of Kumar Lab",
  description: "Score a public MCP server in seconds and red-team your own chatbot with prompt-injection probes. Heuristic, read-only, honest about limits.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
