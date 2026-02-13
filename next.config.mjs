/** @type {import('next').NextConfig} */
const nextConfig = {
  // Disable X-Powered-By header for security
  poweredByHeader: false,

  // Security headers configured in middleware.ts

  // Enable strict mode for React
  reactStrictMode: true,

  // Experimental features
  experimental: {
    // Enable server actions
    serverActions: {
      bodySizeLimit: '1mb',
    },
  },
};

export default nextConfig;
