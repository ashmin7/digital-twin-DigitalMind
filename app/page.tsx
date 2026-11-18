"use client"

import { useMemo, useState } from "react"
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  BookOpen,
  Check,
  ChevronDown,
  Clock3,
  Command,
  Crosshair,
  FileSearch,
  Filter,
  Flag,
  Globe2,
  LockKeyhole,
  Menu,
  Radio,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
  Zap,
} from "lucide-react"

const labs = [
  { title: "Harden the perimeter", category: "Defensive ops", level: "Beginner", time: "12 min", icon: ShieldCheck, accent: "mint", description: "Review a fictional service configuration and close common security gaps." },
  { title: "Trace the signal", category: "Threat hunting", level: "Intermediate", time: "18 min", icon: FileSearch, accent: "blue", description: "Follow a suspicious login through a curated, synthetic event timeline." },
  { title: "Spot the phish", category: "Awareness", level: "Beginner", time: "8 min", icon: Radio, accent: "amber", description: "Inspect a mock message and learn the clues that reveal social engineering." },
  { title: "Map the attack surface", category: "Threat modeling", level: "Intermediate", time: "20 min", icon: Crosshair, accent: "violet", description: "Model a sample application, prioritize risks, and plan mitigations." },
  { title: "Read the headers", category: "Web security", level: "Beginner", time: "10 min", icon: Globe2, accent: "blue", description: "Explore a safe response-header exercise and improve a demo configuration." },
  { title: "Incident first response", category: "Incident response", level: "Advanced", time: "25 min", icon: Activity, accent: "rose", description: "Triage a contained incident scenario and document your response decisions." },
]

const filters = ["All labs", "Defensive ops", "Threat hunting", "Awareness"]

export default function Home() {
  const [activeFilter, setActiveFilter] = useState("All labs")
  const [search, setSearch] = useState("")
  const [activeLab, setActiveLab] = useState<string | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  const visibleLabs = useMemo(() => labs.filter((lab) => {
    const matchesFilter = activeFilter === "All labs" || lab.category === activeFilter
    const matchesSearch = `${lab.title} ${lab.category} ${lab.description}`.toLowerCase().includes(search.toLowerCase())
    return matchesFilter && matchesSearch
  }), [activeFilter, search])

  return (
    <main className="lab-shell min-h-screen bg-[#0b1116] text-[#e8eff1]">
      <aside className={`lab-sidebar ${mobileNavOpen ? "lab-sidebar-open" : ""}`}>
        <div className="flex items-center gap-3 px-6 py-7">
          <div className="grid size-9 place-items-center rounded-xl bg-[#b8f36b] text-[#13200c]"><Shield size={19} strokeWidth={2.5} /></div>
          <div><p className="text-sm font-bold tracking-wide">DIGITAL TWIN III</p><p className="text-[10px] uppercase tracking-[0.2em] text-[#75848c]">Cyber range</p></div>
          <button onClick={() => setMobileNavOpen(false)} className="ml-auto rounded-md p-1 text-[#8b989d] md:hidden" aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="px-4 pb-5"><div className="flex items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 py-2 text-xs text-[#75848c]"><Command size={13} /><span>Search anything</span><kbd className="ml-auto rounded border border-white/10 px-1.5 py-0.5 text-[10px]">⌘ K</kbd></div></div>
        <p className="px-6 pb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[#65747c]">Workspace</p>
        <nav aria-label="Main navigation" className="flex flex-col gap-1 px-3">
          <a href="#overview" className="side-link side-link-active"><Activity size={16} />Overview</a>
          <a href="#labs" className="side-link"><Terminal size={16} />Training labs<span className="ml-auto rounded-full bg-white/[0.08] px-2 py-0.5 text-[10px]">06</span></a>
          <a href="#progress" className="side-link"><Flag size={16} />My progress</a>
          <a href="#field-guide" className="side-link"><BookOpen size={16} />Field guide</a>
        </nav>
        <div className="mx-5 my-6 border-t border-white/[0.07]" />
        <div className="mx-4 rounded-xl border border-[#b8f36b]/15 bg-[#b8f36b]/[0.055] p-4">
          <div className="mb-3 flex items-center gap-2 text-[#b8f36b]"><LockKeyhole size={14} /><span className="text-[10px] font-semibold uppercase tracking-[0.14em]">Safe by design</span></div>
          <p className="text-xs leading-relaxed text-[#9ca9a8]">Every exercise runs on fictional scenarios and isolated training materials.</p>
        </div>
        <div className="mt-auto border-t border-white/[0.07] p-4">
          <button className="flex w-full items-center gap-3 rounded-lg p-2 text-left hover:bg-white/[0.04]">
            <div className="grid size-8 place-items-center rounded-full bg-[#243a35] text-xs font-semibold text-[#b8f36b]">AA</div><div className="min-w-0 flex-1"><p className="truncate text-xs font-medium">Ashmin Aryal</p><p className="text-[10px] text-[#75848c]">Creator · Cybersecurity student</p></div><ChevronDown size={14} className="text-[#75848c]" />
          </button>
        </div>
      </aside>

      <section className="lab-main" id="overview">
        <header className="flex h-[70px] items-center justify-between border-b border-white/[0.07] px-5 md:px-10">
          <div className="flex items-center gap-3"><button className="rounded-lg p-2 text-[#a1adb1] md:hidden" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={19} /></button><div className="hidden items-center gap-2 text-xs text-[#74828a] sm:flex"><span>Workspace</span><span>/</span><span className="text-[#dce4e5]">Overview</span></div><span className="text-sm font-semibold sm:hidden">Overview</span></div>
          <div className="flex items-center gap-3"><span className="hidden rounded-full border border-[#b8f36b]/20 bg-[#b8f36b]/[0.06] px-3 py-1.5 text-[10px] font-medium text-[#b8f36b] sm:inline-flex"><span className="mr-2 mt-1 size-1.5 rounded-full bg-[#b8f36b]" />TRAINING ENVIRONMENT</span><button className="relative rounded-lg border border-white/[0.08] p-2 text-[#9aa7aa] hover:bg-white/[0.04]" aria-label="Notifications"><Bell size={16} /><span className="absolute right-1.5 top-1.5 size-1.5 rounded-full bg-[#b8f36b]" /></button></div>
        </header>

        <div className="mx-auto max-w-[1320px] px-5 pb-16 pt-8 md:px-10 md:pt-10">
          <div className="mb-9 flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
            <div><p className="mb-3 flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.18em] text-[#b8f36b]"><span className="size-1.5 rounded-full bg-[#b8f36b]" />Tuesday, November 18, 2026</p><h1 className="text-3xl font-semibold tracking-[-0.04em] text-[#edf2f1] md:text-[40px]">Welcome to my cyber range<span className="text-[#b8f36b]">.</span></h1><p className="mt-2 text-sm text-[#89979c]">I&apos;m Ashmin Aryal. Explore the lab I built to practice web security and defensive thinking.</p></div>
            <button onClick={() => document.getElementById("labs")?.scrollIntoView({ behavior: "smooth" })} className="flex w-fit items-center gap-2 rounded-lg bg-[#b8f36b] px-4 py-2.5 text-xs font-semibold text-[#14200e] transition hover:bg-[#c9ff83]">Pick up a lab <ArrowRight size={15} /></button>
          </div>

          <div className="mb-8 grid gap-4 md:grid-cols-3">
            <article className="stat-card"><div className="flex items-start justify-between"><div><p className="text-xs text-[#89979c]">Learning streak</p><p className="mt-3 text-3xl font-semibold tracking-tight">04 <span className="text-sm font-normal text-[#89979c]">days</span></p></div><span className="stat-icon text-[#b8f36b]"><Zap size={17} /></span></div><div className="mt-4 flex items-center gap-2 text-[10px] text-[#b8f36b]"><ArrowUpRight size={13} />You’re building a habit</div></article>
            <article className="stat-card"><div className="flex items-start justify-between"><div><p className="text-xs text-[#89979c]">Labs completed</p><p className="mt-3 text-3xl font-semibold tracking-tight">08 <span className="text-sm font-normal text-[#89979c]">/ 24</span></p></div><span className="stat-icon text-[#7ec9ed]"><Check size={17} /></span></div><div className="mt-4 h-1.5 overflow-hidden rounded-full bg-white/[0.07]"><div className="h-full w-1/3 rounded-full bg-[#7ec9ed]" /></div></article>
            <article className="stat-card"><div className="flex items-start justify-between"><div><p className="text-xs text-[#89979c]">Practice time</p><p className="mt-3 text-3xl font-semibold tracking-tight">3.5 <span className="text-sm font-normal text-[#89979c]">hrs</span></p></div><span className="stat-icon text-[#d3a7ff]"><Clock3 size={17} /></span></div><div className="mt-4 flex items-center gap-2 text-[10px] text-[#a9b3b5]"><ArrowDownRight size={13} className="text-[#b8f36b]" />45 min this week</div></article>
          </div>

          <section id="progress" className="mb-10 grid gap-5 lg:grid-cols-[1.45fr_1fr]">
            <article className="feature-card relative overflow-hidden">
              <div className="feature-orb" aria-hidden="true" /><div className="relative z-10 max-w-lg">
                <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-[#b8f36b]/20 bg-[#b8f36b]/[0.07] px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.12em] text-[#b8f36b]"><ShieldAlert size={13} />Continue learning</div>
                <p className="mb-2 text-[10px] uppercase tracking-[0.15em] text-[#829092]">Your current path · Module 03</p><h2 className="text-2xl font-semibold tracking-tight">Foundations of threat hunting</h2><p className="mt-2 max-w-md text-xs leading-relaxed text-[#9aa7aa]">Learn to recognize patterns in sample security events and distinguish signal from noise.</p>
                <div className="mt-6 flex flex-wrap items-center gap-4"><button onClick={() => setActiveLab("Trace the signal")} className="inline-flex items-center gap-2 rounded-lg bg-[#b8f36b] px-4 py-2.5 text-xs font-semibold text-[#14200e] hover:bg-[#c9ff83]">Resume module <ArrowRight size={14} /></button><span className="flex items-center gap-1.5 text-[10px] text-[#94a1a3]"><Clock3 size={13} />18 min left</span></div>
                <div className="mt-6 max-w-xs"><div className="mb-2 flex justify-between text-[10px] text-[#91a0a2]"><span>Path progress</span><span>62%</span></div><div className="h-1 rounded-full bg-white/[0.08]"><div className="h-full w-[62%] rounded-full bg-[#b8f36b]" /></div></div>
              </div>
            </article>
            <article className="path-card"><div className="flex items-center justify-between"><div><p className="text-xs text-[#89979c]">Your learning path</p><h2 className="mt-1 text-lg font-semibold">Blue team essentials</h2></div><div className="grid size-10 place-items-center rounded-xl border border-[#7ec9ed]/20 bg-[#7ec9ed]/[0.08] text-[#7ec9ed]"><Shield size={18} /></div></div><div className="mt-6 flex items-end gap-2"><span className="text-3xl font-semibold">62%</span><span className="mb-1 text-[10px] text-[#89979c]">completed</span></div><div className="mt-3 h-1.5 rounded-full bg-white/[0.07]"><div className="h-full w-[62%] rounded-full bg-[#7ec9ed]" /></div><div className="mt-6 flex flex-col gap-3"><div className="path-step"><span className="step-done"><Check size={11} /></span><span>Security fundamentals</span><span className="ml-auto text-[#b8f36b]">Done</span></div><div className="path-step"><span className="step-current"><span /></span><span>Threat hunting</span><span className="ml-auto text-[#7ec9ed]">In progress</span></div><div className="path-step opacity-50"><span className="step-upcoming" /><span>Incident response</span><span className="ml-auto">Next</span></div></div></article>
          </section>

          <section id="labs">
            <div className="mb-5 flex flex-col justify-between gap-4 md:flex-row md:items-end"><div><div className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-[0.18em] text-[#b8f36b]"><span className="size-1.5 rounded-full bg-[#b8f36b]" />Practice library</div><h2 className="mt-2 text-2xl font-semibold tracking-tight">Choose your next exercise</h2><p className="mt-1 text-xs text-[#89979c]">Short, guided scenarios built for safe hands-on learning.</p></div><div className="relative w-full md:w-64"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#74828a]" /><input aria-label="Search labs" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search the library..." className="w-full rounded-lg border border-white/[0.09] bg-white/[0.025] py-2.5 pl-9 pr-3 text-xs text-[#e8eff1] outline-none transition placeholder:text-[#65747c] focus:border-[#b8f36b]/40" /></div></div>
            <div className="mb-5 flex flex-wrap items-center gap-2"><Filter size={14} className="mr-1 text-[#65747c]" />{filters.map((filter) => <button key={filter} onClick={() => setActiveFilter(filter)} className={`rounded-full border px-3 py-1.5 text-[10px] transition ${activeFilter === filter ? "border-[#b8f36b]/30 bg-[#b8f36b]/[0.08] text-[#b8f36b]" : "border-white/[0.08] text-[#89979c] hover:border-white/20 hover:text-[#dce4e5]"}`}>{filter}</button>)}</div>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {visibleLabs.map((lab) => { const Icon = lab.icon; return <article key={lab.title} className="lab-card"><div className="mb-4 flex items-start justify-between"><span className={`lab-icon lab-icon-${lab.accent}`}><Icon size={18} /></span><span className="rounded-full border border-white/[0.08] px-2.5 py-1 text-[9px] text-[#96a2a5]">{lab.level}</span></div><p className="mb-1 text-[10px] font-medium text-[#7f8e92]">{lab.category}</p><h3 className="text-sm font-semibold text-[#e4ebeb]">{lab.title}</h3><p className="mt-2 min-h-[36px] text-[11px] leading-relaxed text-[#89979c]">{lab.description}</p><div className="mt-5 flex items-center justify-between border-t border-white/[0.06] pt-3"><span className="flex items-center gap-1.5 text-[10px] text-[#7e8b90]"><Clock3 size={12} />{lab.time}</span><button onClick={() => setActiveLab(lab.title)} className="flex items-center gap-1.5 text-[10px] font-semibold text-[#b8f36b] hover:text-[#d0ffa1]">Open lab <ArrowRight size={12} /></button></div></article> })}
            </div>
            {visibleLabs.length === 0 && <div className="rounded-xl border border-dashed border-white/10 py-12 text-center text-sm text-[#89979c]">No labs match that search. Try another term.</div>}
            <div className="mt-6 flex items-center justify-center"><button className="flex items-center gap-2 rounded-lg border border-white/[0.1] px-4 py-2.5 text-xs text-[#b4c0c1] transition hover:border-white/20 hover:bg-white/[0.03]">View all 24 labs <ArrowRight size={14} /></button></div>
          </section>

          <section id="field-guide" className="mt-11 flex flex-col justify-between gap-4 rounded-xl border border-white/[0.07] bg-white/[0.02] p-5 sm:flex-row sm:items-center"><div className="flex items-start gap-3"><div className="grid size-9 shrink-0 place-items-center rounded-lg bg-white/[0.06] text-[#b8f36b]"><BookOpen size={16} /></div><div><h2 className="text-xs font-semibold">Built for ethical practice</h2><p className="mt-1 max-w-xl text-[10px] leading-relaxed text-[#89979c]">Practice only in these fictional, contained exercises. Real systems require explicit authorization before any security testing.</p></div></div><span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-white/[0.08] px-2.5 py-1.5 text-[9px] text-[#89979c]"><LockKeyhole size={11} />Isolated scenarios</span></section>
          <section aria-labelledby="about-lab-heading" className="mt-11 rounded-2xl border border-[#b8f36b]/15 bg-[#b8f36b]/[0.04] p-5 sm:p-7">
            <div className="grid gap-7 lg:grid-cols-[0.8fr_1.2fr] lg:items-start">
              <div>
                <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-[#b8f36b]">About the creator</p>
                <h2 id="about-lab-heading" className="mt-2 text-xl font-semibold tracking-tight text-[#edf2f1]">A hands-on lab built by Ashmin Aryal.</h2>
                <p className="mt-3 text-xs leading-relaxed text-[#a3afb0]">I&apos;m a final-year Bachelor of Cyber Security student at Victoria University in Sydney. I built Digital Twin III to turn what I&apos;m learning about web security into a safe, practical space for exploring attacks and defenses.</p>
                <p className="mt-3 text-xs leading-relaxed text-[#89979c]">My 10-week cybersecurity analyst internship at AusBiz Consulting also gave me hands-on experience with cloud security, identity protection, and security monitoring.</p>
              </div>
              <div>
                <p className="text-[10px] font-medium uppercase tracking-[0.18em] text-[#b8f36b]">How I made it</p>
                <ol className="mt-3 grid gap-3 sm:grid-cols-3">
                  <li className="rounded-xl border border-white/[0.07] bg-[#0b1116]/60 p-4"><span className="font-mono text-[10px] text-[#b8f36b]">01 · BUILD</span><h3 className="mt-2 text-xs font-semibold text-[#e4ebeb]">Web technologies</h3><p className="mt-2 text-[11px] leading-relaxed text-[#89979c]">Built with Next.js and TypeScript, using Supabase and Vercel.</p></li>
                  <li className="rounded-xl border border-white/[0.07] bg-[#0b1116]/60 p-4"><span className="font-mono text-[10px] text-[#b8f36b]">02 · SIMULATE</span><h3 className="mt-2 text-xs font-semibold text-[#e4ebeb]">Common web threats</h3><p className="mt-2 text-[11px] leading-relaxed text-[#89979c]">Created contained scenarios for SQL injection, XSS, login bypass, and bot traffic.</p></li>
                  <li className="rounded-xl border border-white/[0.07] bg-[#0b1116]/60 p-4"><span className="font-mono text-[10px] text-[#b8f36b]">03 · DEFEND</span><h3 className="mt-2 text-xs font-semibold text-[#e4ebeb]">Protect and monitor</h3><p className="mt-2 text-[11px] leading-relaxed text-[#89979c]">Added secure login, access control, and activity logging to help detect suspicious behavior.</p></li>
                </ol>
                <p className="mt-3 text-[10px] leading-relaxed text-[#76858a]">All scenarios are fictional and designed for authorized, defensive learning—not for testing real systems.</p>
              </div>
            </div>
          </section>
          <footer className="mt-8 flex flex-col justify-between gap-2 border-t border-white/[0.07] pt-5 text-[9px] text-[#637178] sm:flex-row"><span>DIGITAL TWIN III CYBER RANGE <span className="px-1.5">·</span> Learn safely. Defend thoughtfully.</span><span>Fictional training materials · No live targets</span></footer>
        </div>
      </section>

      {activeLab && <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" role="presentation" onClick={(event) => { if (event.target === event.currentTarget) setActiveLab(null) }}><section role="dialog" aria-modal="true" aria-labelledby="lab-dialog-title" className="w-full max-w-md rounded-2xl border border-white/10 bg-[#111a20] p-6 shadow-2xl"><div className="flex items-start justify-between"><div className="grid size-10 place-items-center rounded-xl bg-[#b8f36b]/10 text-[#b8f36b]"><Terminal size={18} /></div><button onClick={() => setActiveLab(null)} aria-label="Close lab details" className="rounded-md p-1 text-[#89979c] hover:bg-white/5"><X size={18} /></button></div><p className="mt-5 text-[10px] font-medium uppercase tracking-[0.15em] text-[#b8f36b]">Contained training exercise</p><h2 id="lab-dialog-title" className="mt-2 text-xl font-semibold">{activeLab}</h2><p className="mt-2 text-sm leading-relaxed text-[#9aa7aa]">This fictional exercise is part of the learning library. Work through the guided scenario, review the defensive takeaways, and keep all practice within authorized environments.</p><div className="mt-5 flex items-start gap-2 rounded-lg border border-[#b8f36b]/15 bg-[#b8f36b]/[0.05] p-3 text-[11px] leading-relaxed text-[#aeb9b7]"><LockKeyhole size={14} className="mt-0.5 shrink-0 text-[#b8f36b]" />No real systems are contacted. The exercise uses sample data and a simulated environment.</div><button onClick={() => setActiveLab(null)} className="mt-5 w-full rounded-lg bg-[#b8f36b] py-2.5 text-xs font-semibold text-[#14200e] hover:bg-[#c9ff83]">Got it <Check size={14} className="ml-1 inline" /></button></section></div>}
    </main>
  )
}
