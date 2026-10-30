import { NextResponse } from "next/server";
export const GET = () => NextResponse.json({ ok: true, service: "kok-mcp-security-gate" });
