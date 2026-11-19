"use client"

import Link from "next/link"
import { BookOpen } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function NotebookLMPage() {
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
            <Link href="/v0-templates" className="text-gray-700 hover:text-purple-600">
              v0 Templates
            </Link>
            <Link href="/notebooklm" className="text-amber-600 font-semibold">
              Notebook LM
            </Link>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-6 py-20">
        {/* Header */}
        <div className="mb-20 text-center">
          <div className="w-24 h-24 bg-amber-600 rounded-3xl flex items-center justify-center mx-auto mb-8">
            <BookOpen className="w-14 h-14 text-white" />
          </div>
          <h1 className="text-6xl font-bold text-gray-900 mb-4">Notebook LM</h1>
          <p className="text-2xl text-gray-600 max-w-2xl mx-auto">
            AI study assistant for learning & document management
          </p>
        </div>

        {/* What is Notebook LM */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">What is Notebook LM?</h2>
          <p className="text-lg text-gray-600 mb-12 max-w-3xl">
            Notebook LM is an AI-powered study assistant that helps you learn more effectively. It uses advanced AI to
            analyze your study materials, answer questions, and create personalized learning resources tailored to your
            needs.
          </p>
        </section>

        {/* How It Helps */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-12">How Notebook LM Makes Studying Easier</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="border-2 border-amber-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">AI-Powered Learning</h3>
              <p className="text-gray-600 leading-relaxed">
                Study with an AI tutor available 24/7. Notebook LM answers your questions instantly and provides
                personalized explanations based on your learning style.
              </p>
            </div>

            <div className="border-2 border-amber-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Summarize Complex Topics</h3>
              <p className="text-gray-600 leading-relaxed">
                The AI assists you in summarizing complex topics into digestible pieces. Understanding difficult
                concepts becomes easier when they're broken down clearly.
              </p>
            </div>

            <div className="border-2 border-amber-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Better Exam Preparation</h3>
              <p className="text-gray-600 leading-relaxed">
                Prepare for exams smarter. AI creates focused study guides and practice questions based on exactly what
                you need to learn.
              </p>
            </div>

            <div className="border-2 border-amber-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Document Management</h3>
              <p className="text-gray-600 leading-relaxed">
                Organize all your notes, files, and resources in one intelligent system. Perfect for managing study
                materials and documents.
              </p>
            </div>
          </div>
        </section>

        {/* Key Features */}
        <section className="mb-20 bg-amber-50 rounded-2xl p-12 border border-amber-200">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">Key Features</h2>
          <div className="space-y-6">
            <div className="flex gap-4">
              <span className="text-amber-600 font-bold text-2xl flex-shrink-0">🎯</span>
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Smart Summarization</h3>
                <p className="text-gray-600">
                  Automatically generates concise summaries of your study materials, saving hours of manual note-taking.
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <span className="text-amber-600 font-bold text-2xl flex-shrink-0">💡</span>
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Interactive Q&A</h3>
                <p className="text-gray-600">
                  Ask questions about any topic and get detailed, contextual answers from your study materials.
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <span className="text-amber-600 font-bold text-2xl flex-shrink-0">📚</span>
              <div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Multi-Source Analysis</h3>
                <p className="text-gray-600">
                  Upload multiple documents, PDFs, and notes. AI synthesizes information across all sources.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="text-center">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">Ready to Level Up?</h2>
          <p className="text-gray-600 mb-8 max-w-2xl mx-auto text-lg">
            Use these powerful developer tools to boost your productivity and master new skills.
          </p>
          <Button asChild className="bg-amber-600 hover:bg-amber-700 px-8 py-6 text-lg">
            <Link href="/">← Back to Home</Link>
          </Button>
        </section>
      </div>
    </div>
  )
}
