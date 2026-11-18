"use client"

import { useState } from "react"
import Link from "next/link"
import {
  GithubIcon,
  GitBranchIcon,
  Zap,
  BookOpen,
  ArrowRight,
  Menu,
  X,
  BrainCircuit,
  Bot,
  ShoppingCart,
  Sparkles,
  Code2,
  ShieldCheck,
  Workflow,
  BriefcaseBusiness,
  Database,
  Rocket,
  LineChart,
} from "lucide-react"
import { Button } from "@/components/ui/button"

const learningSections = [
  {
    eyebrow: "Build with AI",
    title: "AI, tools & technology",
    description: "Understand the ideas and tools changing how people build, learn, and work.",
    topics: [
      { title: "Generative AI", description: "How language, image, and multimodal models turn prompts into useful drafts, ideas, and software.", icon: BrainCircuit, color: "violet", tag: "Core concept" },
      { title: "Claude", description: "Explore Claude for writing, analysis, coding, and working through long documents with context.", icon: Sparkles, color: "orange", tag: "AI assistant" },
      { title: "AI agents", description: "Learn how agents combine a model, tools, and a goal to complete multi-step tasks with human oversight.", icon: Bot, color: "blue", tag: "Emerging tech" },
      { title: "Prompt engineering", description: "Give AI clear context, constraints, examples, and success criteria for more reliable results.", icon: BookOpen, color: "amber", tag: "Practical skill" },
      { title: "AI coding tools", description: "Use coding assistants to explore unfamiliar code, generate tests, and speed up everyday development.", icon: Code2, color: "cyan", tag: "Developer tools" },
      { title: "AI automation", description: "Connect repetitive tasks into workflows, and keep approvals in place for consequential actions.", icon: Workflow, color: "emerald", tag: "Productivity" },
      { title: "Data & machine learning", description: "A friendly introduction to datasets, model training, evaluation, and responsible use of predictions.", icon: Database, color: "indigo", tag: "Technology" },
      { title: "AI safety & privacy", description: "Check outputs, protect sensitive information, and understand bias, permissions, and data handling.", icon: ShieldCheck, color: "rose", tag: "Work smarter" },
    ],
  },
  {
    eyebrow: "Start something",
    title: "Online business & careers",
    description: "Get grounded introductions to modern business models and the skills behind them.",
    topics: [
      { title: "Dropshipping basics", description: "Understand the supplier-fulfilled retail model, margins, shipping expectations, and customer service.", icon: ShoppingCart, color: "cyan", tag: "E-commerce" },
      { title: "AI dropshipping", description: "See where AI can help with product research, product descriptions, support, and creative testing—without promising easy profits.", icon: Rocket, color: "violet", tag: "AI + business" },
      { title: "E-commerce essentials", description: "Learn how storefronts, product pages, checkout, fulfillment, and returns fit together.", icon: LineChart, color: "emerald", tag: "Business skills" },
      { title: "Future-ready skills", description: "Build durable skills in communication, critical thinking, digital literacy, and learning new tools.", icon: BriefcaseBusiness, color: "amber", tag: "Career growth" },
    ],
  },
]

const topicStyles: Record<string, string> = {
  violet: "border-violet-200 text-violet-600",
  orange: "border-orange-200 text-orange-600",
  blue: "border-blue-200 text-blue-600",
  amber: "border-amber-200 text-amber-600",
  cyan: "border-cyan-200 text-cyan-600",
  emerald: "border-emerald-200 text-emerald-600",
  indigo: "border-indigo-200 text-indigo-600",
  rose: "border-rose-200 text-rose-600",
}

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

        <div className="mt-28 space-y-24 text-left">
          {learningSections.map((section) => (
            <section key={section.title} aria-labelledby={`${section.title.replaceAll(" ", "-")}-heading`}>
              <div className="mb-10 max-w-2xl">
                <p className="mb-3 text-sm font-semibold uppercase tracking-[0.18em] text-blue-600">{section.eyebrow}</p>
                <h2 id={`${section.title.replaceAll(" ", "-")}-heading`} className="text-3xl font-bold text-gray-900 md:text-4xl">{section.title}</h2>
                <p className="mt-4 text-lg leading-relaxed text-gray-600">{section.description}</p>
              </div>
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
                {section.topics.map((topic) => {
                  const Icon = topic.icon
                  return (
                    <article key={topic.title} className={`group rounded-2xl border bg-white p-7 shadow-sm transition duration-200 hover:-translate-y-1 hover:shadow-lg ${topicStyles[topic.color]}`}>
                      <div className="mb-5 flex items-center justify-between gap-3">
                        <Icon aria-hidden="true" className="size-10 transition-transform group-hover:scale-110" />
                        <span className="rounded-full bg-gray-50 px-3 py-1 text-xs font-medium text-gray-600">{topic.tag}</span>
                      </div>
                      <h3 className="mb-3 text-xl font-bold text-gray-900">{topic.title}</h3>
                      <p className="text-base leading-relaxed text-gray-600">{topic.description}</p>
                    </article>
                  )
                })}
              </div>
            </section>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 bg-gray-50 py-12">
        <div className="max-w-6xl mx-auto px-6 text-center text-gray-600">{/* LinkedIn sharing prompt removed */}</div>
      </footer>
    </div>
  )
}
