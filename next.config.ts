import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    // Correlation log uploads (e.g. full Suricata eve.json) can be hundreds of
    // MB; raise the proxy body buffer above the 10MB default so /api/correlate
    // receives the whole multipart body instead of a truncated one.
    proxyClientMaxBodySize: "512mb",
  },
};

export default nextConfig;
