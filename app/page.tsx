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
              <p className="mt-3 text-gray-600">Choose a tool by the kind of work you need to do, then verify important output before you rely on it.</p>
              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">New and notable</p>
                  <ul className="mt-3 flex flex-col gap-4 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">Gemini 4 Carbon + Google Antigravity</strong><br />Positioned for long coding and research tasks. Antigravity&apos;s swarm approach can split a broad prompt into coordinated agent tasks; review the plan, intermediate work, and final output.</li>
                    <li><strong className="text-gray-800">Claude Meetings</strong><br />A meeting companion that can draft an agenda or plan, capture discussion notes, and extract action items. Tell participants when an AI note taker is present and check the notes before sharing.</li>
                    <li><strong className="text-gray-800">TK by Medium</strong><br />A private notebook for journaling and developing ideas, with a community layer and an MCP connection for working with AI tools. A fit for writers who want a dedicated thinking space.</li>
                  </ul>
                </div>
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Pick a coding workflow</p>
                  <ul className="mt-3 flex flex-col gap-4 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">Cursor</strong> — an AI-focused editor for asking questions and making changes in your code as you work.</li>
                    <li><strong className="text-gray-800">Claude Code</strong> — a coding agent suited to multi-step changes across a repository; inspect its proposed edits and run your project checks.</li>
                    <li><strong className="text-gray-800">OpenAI Codex</strong> — delegate coding tasks to cloud agents, including parallel tasks when work can be separated.</li>
                    <li><strong className="text-gray-800">GitHub Copilot</strong> — inline suggestions and chat in supported editors; a convenient starting point if your workflow already centers on GitHub.</li>
                  </ul>
                </div>
                <div className="rounded-xl bg-white p-5 sm:col-span-2">
                  <p className="font-semibold text-gray-900">Notes, meetings & team knowledge</p>
                  <div className="mt-3 grid gap-4 sm:grid-cols-3">
                    <p className="text-sm leading-6 text-gray-600"><strong className="text-gray-800">Obsidian</strong><br />Local Markdown notes connected by links. Useful for a personal knowledge base; its CLI can support scripting and automation.</p>
                    <p className="text-sm leading-6 text-gray-600"><strong className="text-gray-800">Granola</strong><br />AI meeting notes designed to capture your own notes without a visible bot joining the call. Review transcripts and summaries for accuracy.</p>
                    <p className="text-sm leading-6 text-gray-600"><strong className="text-gray-800">Evernote & Tana</strong><br />Evernote combines notebooks with AI-assisted search and meeting notes. Tana connects structured notes and can turn them into shared team knowledge.</p>
                  </div>
                </div>
              </div>
            </article>

            <article className="rounded-2xl border border-amber-200 bg-amber-50/50 p-7 md:p-8">
              <div className="flex items-center gap-3">
                <NotebookPen className="size-7 text-amber-600" aria-hidden="true" />
                <h3 className="text-2xl font-bold text-gray-900">Study & learning</h3>
              </div>
              <p className="mt-3 text-gray-600">Build a simple learning loop: gather trusted sources, ask focused questions, make your own notes, and test your recall.</p>
              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Study assistants</p>
                  <ul className="mt-3 flex flex-col gap-4 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">NotebookLM</strong><br />Add class readings or your own documents, then ask questions tied to those sources. Use it to make a study guide or clarify a concept, and check the citations against the original material.</li>
                    <li><strong className="text-gray-800">Zoho Notebook</strong><br />Keep class notes, lists, and references organized in notebooks; explore its student-focused AI features where available.</li>
                    <li><strong className="text-gray-800">Recall</strong><br />Save articles, videos, or podcasts and use summaries as a quick review layer. Keep the original source for details and context.</li>
                  </ul>
                </div>
                <div className="rounded-xl bg-white p-5">
                  <p className="font-semibold text-gray-900">Research & standards</p>
                  <ul className="mt-3 flex flex-col gap-4 text-sm leading-6 text-gray-600">
                    <li><strong className="text-gray-800">Elicit</strong><br />Find relevant academic papers and extract comparable details to support a literature review. Confirm study methods and findings in each paper.</li>
                    <li><strong className="text-gray-800">Agent Skills</strong><br />A format for reusable instructions that help compatible AI agents follow a repeatable workflow. Useful for standardizing tasks such as code review or research. <a className="text-blue-700 underline underline-offset-2" href="https://agentskills.io" target="_blank" rel="noreferrer">Learn more</a>.</li>
                    <li><strong className="text-gray-800">MCP</strong><br />Model Context Protocol lets compatible AI tools connect to external apps and data through a shared interface. Consider permissions carefully before connecting sensitive accounts. <a className="text-blue-700 underline underline-offset-2" href="https://modelcontextprotocol.io" target="_blank" rel="noreferrer">Explore MCP</a>.</li>
                  </ul>
                </div>
              </div>
              <p className="mt-5 rounded-lg bg-amber-100/70 p-4 text-sm leading-6 text-amber-950">For coursework, follow your institution&apos;s AI policy. AI summaries can omit context or make mistakes; cite the original source and write final explanations in your own words.</p>
            </article>

            <article className="rounded-2xl border border-emerald-200 bg-emerald-50/50 p-7 md:p-8 lg:col-span-2">
              <div className="grid gap-8 md:grid-cols-[0.8fr_1.2fr] md:items-start">
                <div>
                  <div className="flex items-center gap-3">
                    <ShoppingBag className="size-7 text-emerald-700" aria-hidden="true" />
                    <h3 className="text-2xl font-bold text-gray-900">Dropshipping & AI dropshipping</h3>
                  </div>
                  <p className="mt-3 leading-7 text-gray-600">
                    In dropshipping, your store takes the order while a third-party supplier stores and ships the item. You still own the customer experience: pricing, accurate product information, support, refunds, and clear delivery expectations. AI dropshipping means using AI tools to assist parts of that work—it does not remove the need to verify suppliers or comply with the law.
                  </p>
                  <p className="mt-4 text-sm leading-6 text-gray-600"><strong className="text-gray-800">A useful mental model:</strong> You are responsible for the promise your store makes, even when another company fulfills the package.</p>
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">1. Choose a customer problem</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Start with a defined audience and need, not a viral-product list. Read reviews and community discussions to learn what people value, what disappoints them, and what alternatives they already use.</p>
                  </div>
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">2. Vet products & suppliers</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Order samples where possible. Confirm stock consistency, packaging, tracking, delivery ranges, return handling, product safety, and who pays for defects or lost parcels.</p>
                  </div>
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">3. Calculate true margin</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Subtract product and shipping costs, transaction and platform fees, taxes, ad spend, discounts, refunds, and chargebacks from the sale price. Model a conservative scenario before launch.</p>
                  </div>
                  <div className="rounded-xl bg-white p-5">
                    <p className="font-semibold text-gray-900">4. Build trust & test small</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Publish truthful photos and descriptions, clear delivery windows, contact details, and a workable refund policy. Test a small campaign and pause if service quality or unit economics are poor.</p>
                  </div>
                  <div className="rounded-xl bg-white p-5 sm:col-span-2">
                    <p className="font-semibold text-gray-900">Where AI can help—and where it cannot</p>
                    <p className="mt-2 text-sm leading-6 text-gray-600">Use AI to cluster review themes, outline product comparisons, draft and translate listing copy, generate customer-service templates, or summarize campaign results. Check source data, edit for accuracy and brand voice, and never invent reviews, certifications, inventory, shipping promises, or product benefits. AI cannot validate a supplier, guarantee sales, or replace your legal and customer-service responsibilities.</p>
                  </div>
                </div>
              </div>
              <p className="mt-5 flex items-center gap-2 text-sm text-emerald-900">
                <Users className="size-4 shrink-0" aria-hidden="true" />
                Before accepting orders, check the consumer, tax, privacy, product-safety, and advertising rules that apply in your location and to your customers.
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
