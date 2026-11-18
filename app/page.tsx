"use client"

import { useState } from "react"
import Link from "next/link"
import { GithubIcon, GitBranchIcon, Zap, BookOpen, ArrowRight, Menu, X, Sparkles, ShoppingBag, NotebookPen, Users } from "lucide-react"
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

        <section aria-labelledby="ai-tools-heading" className="mt-32 text-left">
          <div className="max-w-3xl mb-10">
            <p className="text-sm font-semibold uppercase tracking-[0.18em] text-blue-600">Explore more</p>
            <h2 id="ai-tools-heading" className="mt-3 text-4xl font-bold tracking-tight text-gray-900 md:text-5xl">
              AI tools for work, study & ideas
            </h2>
            <p className="mt-4 text-lg leading-8 text-gray-600">
              A practical guide to the newest AI products, useful skills, and ways to put them to work.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <article className="rounded-2xl border border-indigo-200 bg-indigo-50/50 p-7 md:p-8">
              <div className="flex items-center gap-3">
                <Sparkles className="size-7 text-indigo-600" aria-hidden="true" />
                <h3 className="text-2xl font-bold text-gray-900">AI tools worth knowing</h3>
              </div>
              <p className="mt-3 text-gray-600">New releases and useful tools for building, thinking, and keeping track of ideas.</p>
              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Fresh releases</p>
                  <ul className="mt-3 flex flex-col gap-3 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">Gemini 4 Carbon + Google Antigravity</strong> — long-running coding and research tasks, with multi-agent workflows.</li>
                    <li><strong className="text-gray-800">Claude Meetings</strong> — meeting plans, notes, and action items for Google Meet.</li>
                    <li><strong className="text-gray-800">TK by Medium</strong> — a private notebook and journal for writing to think.</li>
                  </ul>
                </div>
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Coding & notes</p>
                  <ul className="mt-3 flex flex-col gap-3 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">Cursor, Claude Code, Codex, Copilot</strong> — AI coding assistants for different development workflows.</li>
                    <li><strong className="text-gray-800">Obsidian, Granola, Evernote</strong> — personal notes, meeting capture, and AI-assisted search.</li>
                    <li><strong className="text-gray-800">Tana</strong> — connected notes designed to become shared team work.</li>
                  </ul>
                </div>
              </div>
            </article>

            <article className="rounded-2xl border border-amber-200 bg-amber-50/50 p-7 md:p-8">
              <div className="flex items-center gap-3">
                <NotebookPen className="size-7 text-amber-600" aria-hidden="true" />
                <h3 className="text-2xl font-bold text-gray-900">Study & learning</h3>
              </div>
              <p className="mt-3 text-gray-600">Find a tool that fits how you collect sources, review, and remember what you learn.</p>
              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Study assistants</p>
                  <ul className="mt-3 flex flex-col gap-3 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">NotebookLM</strong> — study and ask questions grounded in your own sources.</li>
                    <li><strong className="text-gray-800">Zoho Notebook</strong> — notes with AI features for students.</li>
                    <li><strong className="text-gray-800">Recall</strong> — save and summarize articles, videos, and podcasts.</li>
                  </ul>
                </div>
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Research & standards</p>
                  <ul className="mt-3 flex flex-col gap-3 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">Elicit</strong> — search academic papers and organize research findings.</li>
                    <li><strong className="text-gray-800">Agent Skills</strong> — reusable workflows that teach AI agents how to perform a task. <a className="text-blue-700 underline underline-offset-2" href="https://agentskills.io" target="_blank" rel="noreferrer">Learn more</a>.</li>
                    <li><strong className="text-gray-800">MCP</strong> — a standard for connecting AI assistants to apps and data. <a className="text-blue-700 underline underline-offset-2" href="https://modelcontextprotocol.io" target="_blank" rel="noreferrer">Explore MCP</a>.</li>
                  </ul>
                </div>
              </div>
            </article>

            <article className="rounded-2xl border border-emerald-200 bg-emerald-50/50 p-7 md:p-8 lg:col-span-2">
              <div className="grid gap-8 md:grid-cols-[0.8fr_1.2fr] md:items-start">
                <div>
                  <div className="flex items-center gap-3">
                    <ShoppingBag className="size-7 text-emerald-700" aria-hidden="true" />
                    <h3 className="text-2xl font-bold text-gray-900">Dropshipping & AI dropshipping</h3>
                  </div>
                  <p className="mt-3 leading-7 text-gray-600">
                    Dropshipping is an ecommerce model where a supplier ships products directly to customers. AI can help with research and routine work, but it cannot guarantee demand or profit.
                  </p>
                </div>
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">1. Validate first</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Research customer needs and competition. Check supplier reliability, shipping times, returns, and product quality before listing.</p>
                  </div>
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">2. Use AI as a helper</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Brainstorm niches, compare product feedback, draft listings, translate copy, and plan customer-support replies. Verify every claim and detail.</p>
                  </div>
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">3. Know the numbers</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Calculate product, shipping, platform, payment, advertising, and refund costs. Follow consumer-protection and advertising rules in your market.</p>
                  </div>
                </div>
              </div>
              <p className="mt-5 flex items-center gap-2 text-sm text-emerald-900">
                <Users className="size-4" aria-hidden="true" />
                Start with a small test and transparent delivery expectations; treat AI suggestions as drafts, not proof of product quality or market demand.
              </p>
            </article>
          </div>
        </section>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 bg-gray-50 py-12">
        <div className="max-w-6xl mx-auto px-6 text-center text-gray-600">{/* LinkedIn sharing prompt removed */}</div>
      </footer>
    </div>
  )
}
