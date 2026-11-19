"use client"

import Link from "next/link"
import { Zap } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function V0TemplatesPage() {
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
            <Link href="/github" className="text-gray-700 hover:text-blue-600">
              GitHub
            </Link>
            <Link href="/git" className="text-gray-700 hover:text-cyan-600">
              Git
            </Link>
            <Link href="/v0-templates" className="text-purple-600 font-semibold">
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
          <div className="w-24 h-24 bg-purple-600 rounded-3xl flex items-center justify-center mx-auto mb-8">
            <Zap className="w-14 h-14 text-white" />
          </div>
          <h1 className="text-6xl font-bold text-gray-900 mb-4">v0 Templates</h1>
          <p className="text-2xl text-gray-600 max-w-2xl mx-auto">AI-powered project templates for rapid development</p>
        </div>

        {/* What are v0 Templates */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">What are v0 Templates?</h2>
          <p className="text-lg text-gray-600 mb-12 max-w-3xl">
            v0 Templates provide solid, production-ready structures to build your projects upon. These are curated
            templates with best practices built in, allowing you to start building immediately instead of spending weeks
            on infrastructure setup.
          </p>
        </section>

        {/* How Templates Save Time */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-12">How v0 Templates Save Time and Effort</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="border-2 border-purple-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Save Development Time</h3>
              <p className="text-gray-600 leading-relaxed">
                Skip weeks of setup work. Templates come with everything you need: folder structures, component
                libraries, styling, and configuration already set up perfectly.
              </p>
            </div>

            <div className="border-2 border-purple-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Easy Project Startup</h3>
              <p className="text-gray-600 leading-relaxed">
                Get started without confusion. Templates eliminate decision paralysis by providing clear, organized
                structures that follow industry best practices.
              </p>
            </div>

            <div className="border-2 border-purple-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Beginner-Friendly Foundation</h3>
              <p className="text-gray-600 leading-relaxed">
                If you're new to development, templates provide a foundation that's easy to understand. Focus on
                learning and building features instead of wrestling with configuration.
              </p>
            </div>

            <div className="border-2 border-purple-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Professional Structure</h3>
              <p className="text-gray-600 leading-relaxed">
                Understand how to set up a "real" project used by professionals. Templates show the right way to
                organize components, pages, styles, and utilities.
              </p>
            </div>
          </div>
        </section>

        {/* Use Cases */}
        <section className="mb-20 bg-purple-50 rounded-2xl p-12 border border-purple-200">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">What You Can Build</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white rounded-lg p-6 border border-purple-200">
              <h3 className="text-lg font-bold text-purple-600 mb-3">📱 Applications</h3>
              <p className="text-gray-600">
                Full-featured web applications with authentication, databases, and real-time functionality.
              </p>
            </div>

            <div className="bg-white rounded-lg p-6 border border-purple-200">
              <h3 className="text-lg font-bold text-purple-600 mb-3">📊 Dashboards</h3>
              <p className="text-gray-600">
                Analytics dashboards with charts, data visualization, and interactive components.
              </p>
            </div>

            <div className="bg-white rounded-lg p-6 border border-purple-200">
              <h3 className="text-lg font-bold text-purple-600 mb-3">⚙️ Automations</h3>
              <p className="text-gray-600">
                Automated workflows and background processes that handle repetitive tasks.
              </p>
            </div>
          </div>
        </section>

        {/* Navigation */}
        <div className="flex justify-center">
          <Button asChild className="bg-purple-600 hover:bg-purple-700 px-8 py-6 text-lg">
            <Link href="/notebooklm">Next: Notebook LM →</Link>
          </Button>
        </div>
      </div>
    </div>
  )
}
