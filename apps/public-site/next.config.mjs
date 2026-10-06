/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: [],
  async headers() {
    const headers = [
      { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
      { key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=()" },
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" }
    ];
    if (process.env.NODE_ENV === "production") headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000" });
    return [{ source: "/:path*", headers }];
  }
};

export default nextConfig;
