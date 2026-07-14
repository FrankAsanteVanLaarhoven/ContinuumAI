import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // @continuum/core ships as TypeScript source and must be transpiled by Next.
  transpilePackages: ["@continuum/core"],
  // Pin the monorepo root so build tracing ignores unrelated lockfiles.
  outputFileTracingRoot: resolve(here, "../.."),
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: false },
};

export default nextConfig;
