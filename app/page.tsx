"use client"

import { useState } from "react"
import Link from "next/link"
import { GithubIcon, GitBranchIcon, Zap, BookOpen, ArrowRight, Menu, X } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function Home() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="min-h-screen bg-white text-gray-900">
      <header className="sticky top-0 z-50 border-b border-gray-200 bg-white/90 backdrop-blur-md">
        <nav aria-label="Main navigation" className="relative mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <Link href="/" className="bg-gradient-to-r from-blue-600 to-cyan-600 bg-clip-text text-2xl font-bold text-transparent">
            DevTools Guide
          </Link>

          <button
            type="button"
            className="text-gray-800 md:hidden"
            aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={mobileMenuOpen}
            aria-controls="primary-navigation"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
          </button>

          <div
            id="primary-navigation"
            className={`${mobileMenuOpen ? "flex" : "hidden"} absolute left-0 top-full w-full flex-col gap-6 bg-white p-6 md:static md:flex md:w-auto md:flex-row md:gap-8 md:bg-transparent md:p-0`}
          >
            <Link href="/" className="text-gray-700 transition hover:text-blue-600" onClick={() => setMobileMenuOpen(false)}>
              Home
            </Link>
            <Link href="/github" className="text-gray-700 transition hover:text-blue-600" onClick={() => setMobileMenuOpen(false)}>
              GitHub
            </Link>
            <Link href="/git" className="text-gray-700 transition hover:text-blue-600" onClick={() => setMobileMenuOpen(false)}>
              Git
            </Link>
            <Link href="/v0-templates" className="text-gray-700 transition hover:text-blue-600" onClick={() => setMobileMenuOpen(false)}>
              v0 Templates
            </Link>
            <Link href="/notebooklm" className="text-gray-700 transition hover:text-blue-600" onClick={() => setMobileMenuOpen(false)}>
              Notebook LM
            </Link>
          </div>
        </nav>
      </header>

      <main>
        <section className="mx-auto max-w-6xl px-6 py-24 text-center sm:py-32">
          <div className="flex flex-col gap-8">
            <h1 className="text-balance text-5xl font-bold text-gray-900 sm:text-6xl md:text-7xl">
              Master Essential{" "}
              <span className="bg-gradient-to-r from-blue-600 to-cyan-600 bg-clip-text text-transparent">
                Developer Tools
              </span>
            </h1>

            <p className="mx-auto max-w-2xl text-balance text-lg text-gray-600 sm:text-xl">
              Learn how GitHub, Git, v0 Templates, and Notebook LM can transform your development workflow and boost
              productivity
            </p>

            <div>
              <Button className="rounded-xl bg-blue-600 px-8 py-6 text-lg text-white hover:bg-blue-700" asChild>
                <Link href="/github">
                  Start Learning <ArrowRight aria-hidden="true" className="ml-2 size-5" />
                </Link>
              </Button>
            </div>
          </div>

          <div className="mt-20 grid grid-cols-1 gap-6 text-left md:grid-cols-2">
            <Link href="/github" className="group rounded-2xl border border-blue-200 bg-white p-8 transition hover:shadow-lg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-blue-600">
              <GithubIcon aria-hidden="true" className="mb-4 size-12 text-blue-600 transition group-hover:scale-110" />
              <h2 className="mb-3 text-2xl font-bold text-gray-900">GitHub</h2>
              <p className="mb-4 text-gray-600">Cloud hosting &amp; version control for collaborative development</p>
              <span className="flex items-center gap-2 text-blue-600">
                Learn more <ArrowRight aria-hidden="true" className="size-4" />
              </span>
            </Link>

            <Link href="/git" className="group rounded-2xl border border-cyan-200 bg-white p-8 transition hover:shadow-lg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-cyan-600">
              <GitBranchIcon aria-hidden="true" className="mb-4 size-12 text-cyan-600 transition group-hover:scale-110" />
              <h2 className="mb-3 text-2xl font-bold text-gray-900">Git</h2>
              <p className="mb-4 text-gray-600">Version control system for tracking code changes</p>
              <span className="flex items-center gap-2 text-cyan-600">
                Learn more <ArrowRight aria-hidden="true" className="size-4" />
              </span>
            </Link>

            <Link href="/v0-templates" className="group rounded-2xl border border-purple-200 bg-white p-8 transition hover:shadow-lg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-purple-600">
              <Zap aria-hidden="true" className="mb-4 size-12 text-purple-600 transition group-hover:scale-110" />
              <h2 className="mb-3 text-2xl font-bold text-gray-900">v0 Templates</h2>
              <p className="mb-4 text-gray-600">AI-powered project templates for rapid development</p>
              <span className="flex items-center gap-2 text-purple-600">
                Learn more <ArrowRight aria-hidden="true" className="size-4" />
              </span>
            </Link>

            <Link href="/notebooklm" className="group rounded-2xl border border-amber-200 bg-white p-8 transition hover:shadow-lg focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-amber-600">
              <BookOpen aria-hidden="true" className="mb-4 size-12 text-amber-600 transition group-hover:scale-110" />
              <h2 className="mb-3 text-2xl font-bold text-gray-900">Notebook LM</h2>
              <p className="mb-4 text-gray-600">AI study assistant for learning &amp; document management</p>
              <span className="flex items-center gap-2 text-amber-600">
                Learn more <ArrowRight aria-hidden="true" className="size-4" />
              </span>
            </Link>
          </div>
        </section>
      </main>

      <footer className="border-t border-gray-200 bg-gray-50 py-12">
        <div className="mx-auto max-w-6xl px-6 text-center text-gray-600">
          <p>DevTools Guide · Learning notes for modern development</p>
        </div>
      </footer>
    </div>
  )
}
