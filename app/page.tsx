"use client"

import { useMemo, useState } from "react"
import Link from "next/link"
import { ArrowDownRight, ArrowUpRight, BookOpen, Search } from "lucide-react"

const notes = [
  { title: "GitHub: a home for your code", topic: "GitHub", date: "Field guide", read: "6 min read", href: "/github", excerpt: "Repositories, collaboration, and the habits that make working in public projects easier." },
  { title: "Git, without the mystery", topic: "Version control", date: "Field guide", read: "8 min read", href: "/git", excerpt: "A practical mental model for commits, branches, merges, and keeping a useful project history." },
  { title: "Building with v0 templates", topic: "Web development", date: "Workshop notes", read: "5 min read", href: "/v0-templates", excerpt: "Start from a strong foundation, adapt the parts you need, and keep your project moving." },
  { title: "A study companion for curious minds", topic: "Learning tools", date: "Reading notes", read: "4 min read", href: "/notebooklm", excerpt: "A few ways to turn source material into a more focused, useful learning routine." },
]

const topics = ["All notes", "GitHub", "Version control", "Web development", "Learning tools"]

export default function Home() {
  const [activeTopic, setActiveTopic] = useState("All notes")
  const [query, setQuery] = useState("")
  const filteredNotes = useMemo(() => notes.filter((note) => {
    const matchesTopic = activeTopic === "All notes" || note.topic === activeTopic
    const matchesQuery = `${note.title} ${note.topic} ${note.excerpt}`.toLowerCase().includes(query.trim().toLowerCase())
    return matchesTopic && matchesQuery
  }), [activeTopic, query])

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border">
        <nav aria-label="Main navigation" className="mx-auto flex max-w-6xl items-center justify-between px-5 py-5 sm:px-8">
          <Link href="/" className="flex items-center gap-3 font-medium tracking-tight">
            <span className="grid size-9 place-items-center rounded-full bg-primary text-primary-foreground"><BookOpen size={17} aria-hidden="true" /></span>
            <span>Ashmin&apos;s <span className="font-serif italic">notes</span></span>
          </Link>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a className="transition hover:text-foreground" href="#archive">Archive</a>
            <Link className="transition hover:text-foreground" href="/about">About</Link>
          </div>
        </nav>
      </header>

      <main>
        <section className="mx-auto grid max-w-6xl gap-10 px-5 pb-16 pt-16 sm:px-8 sm:pb-20 sm:pt-24 lg:grid-cols-[1.1fr_.9fr] lg:items-end">
          <div>
            <p className="section-label">A personal knowledge garden <span>·</span> Sydney</p>
            <h1 className="mt-6 max-w-3xl font-serif text-5xl leading-[1.04] tracking-[-0.045em] sm:text-6xl lg:text-7xl">Notes on what I&apos;m <em className="text-primary">learning.</em></h1>
          </div>
          <div className="max-w-md lg:justify-self-end">
            <p className="text-base leading-7 text-muted-foreground">A living collection of ideas, field guides, and study notes about technology, building for the web, and learning as I go.</p>
            <a href="#archive" className="mt-6 inline-flex items-center gap-2 text-sm font-medium text-primary transition hover:gap-3">Browse the notes <ArrowDownRight size={16} aria-hidden="true" /></a>
          </div>
        </section>

        <section aria-labelledby="featured-heading" className="mx-auto max-w-6xl px-5 pb-16 sm:px-8 sm:pb-20">
          <div className="grid overflow-hidden rounded-2xl border border-border bg-card md:grid-cols-[1fr_.8fr]">
            <div className="flex flex-col justify-between gap-10 p-7 sm:p-10 lg:p-12">
              <div>
                <p className="section-label">Start here <span>/ 01</span></p>
                <h2 id="featured-heading" className="mt-5 max-w-xl font-serif text-3xl leading-tight tracking-[-0.035em] sm:text-4xl">A small guide to understanding Git</h2>
                <p className="mt-4 max-w-lg leading-7 text-muted-foreground">The core ideas behind version control, explained as a set of notes I wish I had when I started.</p>
              </div>
              <Link href="/git" className="inline-flex w-fit items-center gap-2 border-b border-primary pb-2 text-sm font-medium transition hover:gap-3">Read the field guide <ArrowUpRight size={15} aria-hidden="true" /></Link>
            </div>
            <div aria-hidden="true" className="flex min-h-56 items-center justify-center border-t border-border bg-secondary p-8 md:border-l md:border-t-0">
              <div className="w-full max-w-xs rotate-[-2deg] rounded-xl border border-border bg-background p-6 shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-4"><span className="font-mono text-xs text-muted-foreground">git / basics</span><span className="size-2 rounded-full bg-primary" /></div>
                <div className="mt-6 flex flex-col gap-4 font-mono text-sm"><p><span className="text-primary">$</span> git status</p><p className="pl-5 text-muted-foreground">working tree clean</p><p><span className="text-primary">$</span> git branch</p><p className="pl-5 text-muted-foreground">* main</p></div>
              </div>
            </div>
          </div>
        </section>

        <section id="archive" aria-labelledby="archive-heading" className="border-t border-border bg-secondary/40">
          <div className="mx-auto max-w-6xl px-5 py-14 sm:px-8 sm:py-20">
            <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
              <div><p className="section-label">The notebook <span>/ archive</span></p><h2 id="archive-heading" className="mt-3 font-serif text-3xl tracking-tight sm:text-4xl">Browse all notes</h2></div>
              <label className="flex h-11 items-center gap-3 rounded-lg border border-border bg-background px-3 text-muted-foreground focus-within:ring-2 focus-within:ring-ring">
                <Search size={16} aria-hidden="true" /><span className="sr-only">Search notes</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search the notebook" className="w-52 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground" />
              </label>
            </div>

            <div className="mt-8 flex gap-2 overflow-x-auto pb-2" role="group" aria-label="Filter notes by topic">
              {topics.map((topic) => <button key={topic} type="button" aria-pressed={activeTopic === topic} onClick={() => setActiveTopic(topic)} className={`shrink-0 rounded-full border px-4 py-2 text-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring ${activeTopic === topic ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background text-muted-foreground hover:text-foreground"}`}>{topic}</button>)}
            </div>

            <div className="mt-6 divide-y divide-border border-y border-border">
              {filteredNotes.map((note, index) => (
                <Link key={note.title} href={note.href} className="group grid gap-3 py-6 transition sm:grid-cols-[7rem_1fr_auto] sm:items-center sm:gap-6">
                  <span className="font-mono text-xs text-muted-foreground">{String(index + 1).padStart(2, "0")} <span className="text-primary">/</span> {note.date}</span>
                  <span><span className="text-xs text-primary">{note.topic}</span><span className="mt-1 block font-serif text-xl tracking-tight transition group-hover:text-primary sm:text-2xl">{note.title}</span><span className="mt-2 block max-w-2xl text-sm leading-6 text-muted-foreground">{note.excerpt}</span></span>
                  <span className="flex items-center gap-3 text-xs text-muted-foreground sm:justify-end"><span>{note.read}</span><ArrowUpRight className="transition group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-primary" size={16} aria-hidden="true" /></span>
                </Link>
              ))}
              {filteredNotes.length === 0 && <p className="py-10 text-center text-sm text-muted-foreground">No notes match that search. Try another topic or phrase.</p>}
            </div>
          </div>
        </section>
      </main>

      <footer className="mx-auto flex max-w-6xl flex-col gap-3 px-5 py-8 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-8">
        <p>Made for keeping useful things close.</p><p>notes.ashminaryal.info <span className="px-2 text-primary">·</span> Ashmin Aryal</p>
      </footer>
    </div>
  )
}
