// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  trailingSlash: true, // This ensures URLs end with a slash
  images: {
    unoptimized: true
  },
  webpack: (config) => {
    // Important: return the modified config
    return config;
  }
}

module.exports = nextConfig