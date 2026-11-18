"use client"

import Link from "next/link"
import { GitBranch } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function GitPage() {
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
            <Link href="/git" className="text-cyan-600 font-semibold">
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
          <div className="w-24 h-24 bg-cyan-600 rounded-3xl flex items-center justify-center mx-auto mb-8">
            <GitBranch className="w-14 h-14 text-white" />
          </div>
          <h1 className="text-6xl font-bold text-gray-900 mb-4">Git</h1>
          <p className="text-2xl text-gray-600 max-w-2xl mx-auto">Version control system for tracking code changes</p>
        </div>

        {/* What is Git */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">What is Git?</h2>
          <p className="text-lg text-gray-600 mb-12 max-w-3xl">
            Git is a distributed version control system that allows developers to track changes in their code files.
            Unlike GitHub (which is a platform), Git is the actual tool you install on your computer to manage version
            history locally before pushing to platforms like GitHub.
          </p>
        </section>

        {/* How Git Works */}
        <section className="mb-20">
          <h2 className="text-3xl font-bold text-gray-900 mb-12">How Git Enables Efficient Work</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="border-2 border-cyan-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Save Previous Updates</h3>
              <p className="text-gray-600 leading-relaxed">
                Every time you commit, Git saves a snapshot. All previous updates are preserved, letting you view the
                complete history of your project.
              </p>
            </div>

            <div className="border-2 border-cyan-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Undo Mistakes</h3>
              <p className="text-gray-600 leading-relaxed">
                Made a mistake? Git allows you to revert to any previous version instantly. You can undo changes without
                losing work, making experimentation safe.
              </p>
            </div>

            <div className="border-2 border-cyan-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Better Collaboration</h3>
              <p className="text-gray-600 leading-relaxed">
                Git enables teams to work on the same project using branches. Changes can be merged smoothly, and
                conflicts are managed automatically or resolved manually.
              </p>
            </div>

            <div className="border-2 border-cyan-200 rounded-2xl p-8 bg-white hover:shadow-lg transition">
              <h3 className="text-xl font-bold text-gray-900 mb-4">Detailed Records</h3>
              <p className="text-gray-600 leading-relaxed">
                Keep comprehensive records of your projects with detailed commit messages. Every change is documented
                with context about why it was made.
              </p>
            </div>
          </div>
        </section>

        {/* Essential Commands */}
        <section className="mb-20 bg-cyan-50 rounded-2xl p-12 border border-cyan-200">
          <h2 className="text-3xl font-bold text-gray-900 mb-8">Essential Git Commands</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-white rounded-lg p-6 border border-cyan-200">
              <code className="text-cyan-600 font-mono text-lg font-bold">git add</code>
              <p className="text-gray-600 mt-3">
                Stages changes to be committed. Tells Git which files to include in the next commit.
              </p>
            </div>
            <div className="bg-white rounded-lg p-6 border border-cyan-200">
              <code className="text-cyan-600 font-mono text-lg font-bold">git commit</code>
              <p className="text-gray-600 mt-3">
                Creates a snapshot with a descriptive message. This is saved to your local repository.
              </p>
            </div>
            <div className="bg-white rounded-lg p-6 border border-cyan-200">
              <code className="text-cyan-600 font-mono text-lg font-bold">git push</code>
              <p className="text-gray-600 mt-3">
                Uploads your local commits to a remote repository like GitHub, making them available to your team.
              </p>
            </div>
            <div className="bg-white rounded-lg p-6 border border-cyan-200">
              <code className="text-cyan-600 font-mono text-lg font-bold">git pull</code>
              <p className="text-gray-600 mt-3">
                Downloads the latest changes from the remote repository and merges them into your local code.
              </p>
            </div>
            <div className="bg-white rounded-lg p-6 border border-cyan-200 md:col-span-2">
              <code className="text-cyan-600 font-mono text-lg font-bold">git clone</code>
              <p className="text-gray-600 mt-3">
                Creates a local copy of an entire remote repository on your computer, ready to work on.
              </p>
            </div>
          </div>
        </section>

        {/* Navigation */}
        <div className="flex justify-center">
          <Button asChild className="bg-cyan-600 hover:bg-cyan-700 px-8 py-6 text-lg">
            <Link href="/v0-templates">Next: v0 Templates →</Link>
          </Button>
        </div>
      </div>
    </div>
  )
}
