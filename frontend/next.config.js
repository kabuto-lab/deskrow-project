// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export', // This enables static export
  trailingSlash: true, // This ensures URLs end with a slash
  images: {
    unoptimized: true // Required for static export
  },
  webpack: (config) => {
    // Important: return the modified config
    return config;
  }
}

module.exports = nextConfig