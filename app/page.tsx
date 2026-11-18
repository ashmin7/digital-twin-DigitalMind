"use client"

import { useState } from "react"
import Link from "next/link"
import { GithubIcon, GitBranchIcon, Zap, BookOpen, ArrowRight, Menu, X } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function Home() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="min-h-screen bg-white">
      {/* Navigation */}
      <nav className="sticky top-0 z-50 backdrop-blur-md bg-white/90 border-b border-gray-200">
        <div className="max-w-6xl mx-auto px-6 py-4 flex justify-between items-center">
          <div className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-cyan-600 bg-clip-text text-transparent">
            DevTools Guide
          </div>

          <button className="md:hidden text-gray-800" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
            {mobileMenuOpen ? <X /> : <Menu />}
          </button>

          <div
            className={`${mobileMenuOpen ? "flex" : "hidden"} md:flex gap-8 absolute md:relative top-full left-0 md:top-auto md:left-auto w-full md:w-auto flex-col md:flex-row bg-white md:bg-transparent p-6 md:p-0`}
          >
            <Link href="/" className="text-gray-700 hover:text-blue-600 transition">
              Home
            </Link>
            <Link href="/github" className="text-gray-700 hover:text-blue-600 transition">
              GitHub
            </Link>
            <Link href="/git" className="text-gray-700 hover:text-blue-600 transition">
              Git
            </Link>
            <Link href="/v0-templates" className="text-gray-700 hover:text-blue-600 transition">
              v0 Templates
            </Link>
            <Link href="/notebooklm" className="text-gray-700 hover:text-blue-600 transition">
              Notebook LM
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative max-w-6xl mx-auto px-6 py-32 text-center">
        <div className="space-y-8">
          <h1 className="text-6xl md:text-7xl font-bold text-gray-900 text-balance">
            Master Essential{" "}
            <span className="bg-gradient-to-r from-blue-600 to-cyan-600 bg-clip-text text-transparent">
              Developer Tools
            </span>
          </h1>

          <p className="text-xl text-gray-600 max-w-2xl mx-auto text-balance">
            Learn how GitHub, Git, v0 Templates, and Notebook LM can transform your development workflow and boost
            productivity
          </p>

          <Button className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-6 text-lg rounded-xl" asChild>
            <Link href="/github">
              Start Learning <ArrowRight className="ml-2 w-5 h-5" />
            </Link>
          </Button>
        </div>

        {/* Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-20">
          <Link href="/github">
            <div className="bg-white border border-blue-200 rounded-2xl p-8 hover:shadow-lg transition cursor-pointer group">
              <GithubIcon className="w-12 h-12 text-blue-600 mb-4 group-hover:scale-110 transition" />
              <h3 className="text-2xl font-bold text-gray-900 mb-3">GitHub</h3>
              <p className="text-gray-600 mb-4">Cloud hosting & version control for collaborative development</p>
              <span className="text-blue-600 flex items-center gap-2">
                Learn more <ArrowRight className="w-4 h-4" />
              </span>
            </div>
          </Link>

          <Link href="/git">
            <div className="bg-white border border-cyan-200 rounded-2xl p-8 hover:shadow-lg transition cursor-pointer group">
              <GitBranchIcon className="w-12 h-12 text-cyan-600 mb-4 group-hover:scale-110 transition" />
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Git</h3>
              <p className="text-gray-600 mb-4">Version control system for tracking code changes</p>
              <span className="text-cyan-600 flex items-center gap-2">
                Learn more <ArrowRight className="w-4 h-4" />
              </span>
            </div>
          </Link>

          <Link href="/v0-templates">
            <div className="bg-white border border-purple-200 rounded-2xl p-8 hover:shadow-lg transition cursor-pointer group">
              <Zap className="w-12 h-12 text-purple-600 mb-4 group-hover:scale-110 transition" />
              <h3 className="text-2xl font-bold text-gray-900 mb-3">v0 Templates</h3>
              <p className="text-gray-600 mb-4">AI-powered project templates for rapid development</p>
              <span className="text-purple-600 flex items-center gap-2">
                Learn more <ArrowRight className="w-4 h-4" />
              </span>
            </div>
          </Link>

          <Link href="/notebooklm">
            <div className="bg-white border border-amber-200 rounded-2xl p-8 hover:shadow-lg transition cursor-pointer group">
              <BookOpen className="w-12 h-12 text-amber-600 mb-4 group-hover:scale-110 transition" />
              <h3 className="text-2xl font-bold text-gray-900 mb-3">Notebook LM</h3>
              <p className="text-gray-600 mb-4">AI study assistant for learning & document management</p>
              <span className="text-amber-600 flex items-center gap-2">
                Learn more <ArrowRight className="w-4 h-4" />
              </span>
            </div>
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 bg-gray-50 py-12">
        <div className="max-w-6xl mx-auto px-6 text-center text-gray-600">{/* LinkedIn sharing prompt removed */}</div>
      </footer>
    </div>
  )
}
