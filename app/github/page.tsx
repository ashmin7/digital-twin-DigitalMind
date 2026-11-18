"use client"

import Link from "next/link"
import { Github } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function GitHubPage() {
  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className="border-b border-gray-200 bg-white/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="text-2xl font-bold text-blue-600">DevTools Guide</div>
          <div className="flex gap-8">
            <Link href="/" className="text-gray-700 hover:text-blue-600">
              Home
            </Link>
            <Link href="/github" className="text-blue-600 font-semibold">
              GitHub
            </Link>
            <Link href="/git" className="text-gray-700 hover:text-cyan-600">
              Git
            </Link>
            <Link href="/v0-templates" className="text-gray-700 hover:text-purple-600">
              v0 Templates
            </Link>
            <Link href="/notebooklm" className="text-gray-700 hover:text-amber-600">
              Notebook LM
            </Link>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-6 py-20">
        {/* Header */}
        <div className="mb-20 text-center">
          <div className="w-24 h-24 bg-blue-600 rounded-3xl flex items-center justify-center mx-auto mb-8">
            <Github className="w-14 h-14 text-white" />
          </div>
          <h1 className="text-6xl font-bold text-gray-900 mb-4">GitHub</h1>
          <p className="text-2xl text-gray-600 max-w-2xl mx-auto">
            Cloud hosting & version control for collaborative development
          </p>
        </div>

        {/* What GitHub Can Do */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-12">What GitHub Can Do For You</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="border-2 border-blue-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Code Hosting</h3>
              <p className="text-gray-600 leading-relaxed">
                GitHub hosts your code securely in the cloud, making it accessible from anywhere. Your repositories are
                backed up automatically and protected with industry-standard security.
              </p>
            </div>

            <div className="border-2 border-blue-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Version Control History</h3>
              <p className="text-gray-600 leading-relaxed">
                Track every version of your code. GitHub maintains a complete history of all changes, allowing you to
                see who made what changes and when.
              </p>
            </div>

            <div className="border-2 border-blue-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Team Collaboration</h3>
              <p className="text-gray-600 leading-relaxed">
                Work seamlessly with teams through pull requests, code reviews, and issue tracking. Multiple developers
                can collaborate without overwriting each other's work.
              </p>
            </div>

            <div className="border-2 border-blue-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Portfolio Building</h3>
              <p className="text-gray-600 leading-relaxed">
                Showcase your projects to employers. A well-maintained GitHub profile is highly valued by recruiters and
                essential for any developer's career.
              </p>
            </div>
          </div>
        </section>

        {/* Key Benefits */}
        <section className="mb-20 bg-blue-50 rounded-2xl p-12 border border-blue-200">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">Why GitHub Matters</h2>
          <ul className="space-y-4 text-gray-700">
            <li className="flex gap-3">
              <span className="text-blue-600 font-bold text-xl">✓</span>
              <span>
                <strong>Easy Sharing:</strong> Share projects with the world or keep them private with controlled
                access.
              </span>
            </li>
            <li className="flex gap-3">
              <span className="text-blue-600 font-bold text-xl">✓</span>
              <span>
                <strong>Community:</strong> Join millions of developers and contribute to open-source projects.
              </span>
            </li>
            <li className="flex gap-3">
              <span className="text-blue-600 font-bold text-xl">✓</span>
              <span>
                <strong>Integration:</strong> Connect with CI/CD pipelines, deployment tools, and project management
                platforms.
              </span>
            </li>
            <li className="flex gap-3">
              <span className="text-blue-600 font-bold text-xl">✓</span>
              <span>
                <strong>Security:</strong> Built-in vulnerability scanning and automated dependency updates.
              </span>
            </li>
          </ul>
        </section>

        {/* Navigation */}
        <div className="flex justify-center">
          <Button asChild className="bg-blue-600 hover:bg-blue-700 px-8 py-6 text-lg">
            <Link href="/git">Next: Learn About Git →</Link>
          </Button>
        </div>
      </div>
    </div>
  )
}
