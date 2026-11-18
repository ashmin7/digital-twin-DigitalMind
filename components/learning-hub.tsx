"use client"

import { useMemo, useState } from "react"
import Link from "next/link"
import {
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Atom,
  BookOpen,
  Bot,
  BrainCircuit,
  BriefcaseBusiness,
  Check,
  ChevronDown,
  Code2,
  Compass,
  GitBranch,
  Github,
  Lightbulb,
  LineChart,
  Menu,
  Search,
  ShieldCheck,
  ShoppingBag,
  Sparkles,
  Workflow,
  X,
  Zap,
} from "lucide-react"

const categories = ["All topics", "AI & models", "Build & code", "Business", "Skills"] as const
type Category = (typeof categories)[number]
type Topic = {
  title: string
  category: Exclude<Category, "All topics">
  description: string
  takeaway: string
  whyItMatters: string
  firstStep: string
  watchFor: string
  icon: typeof BrainCircuit
  color: string
  level: string
}

const topics: Topic[] = [
  { title: "Generative AI", category: "AI & models", description: "A practical introduction to models that create text, images, audio, and code from context.", takeaway: "These systems predict useful next pieces from patterns in their training data; they can sound confident and still be wrong.", whyItMatters: "Generative tools are changing how people draft, research, design, and build. Knowing their strengths and limits helps you use them as capable assistants rather than unquestioned authorities.", firstStep: "Ask one model to explain a familiar topic, then verify two claims against a trusted source.", watchFor: "Fluent answers can include invented facts, missing context, or outdated information. Check important claims against reliable sources.", icon: BrainCircuit, color: "purple", level: "Start here" },
  { title: "Claude", category: "AI & models", description: "Explore Claude for careful writing, coding help, analysis, and working with long documents.", takeaway: "Good results come from a clear task, relevant context, and an explicit description of the output you need.", whyItMatters: "Claude can help you think through complex material, turn rough ideas into drafts, and explore code. It is most useful when you provide context and review the result for your specific needs.", firstStep: "Give Claude a short document and ask for a summary with citations to the source sections.", watchFor: "Features, usage limits, and data settings depend on the product and plan. Avoid sharing sensitive information unless you understand the service's privacy terms.", icon: Sparkles, color: "orange", level: "Tool guide" },
  { title: "AI agents", category: "AI & models", description: "Understand how AI systems use tools and multi-step plans to work toward a goal.", takeaway: "An agent is more than a chatbot: it can choose actions, inspect results, and continue within defined permissions.", whyItMatters: "Agents can coordinate multiple steps across tools, making them useful for research and repetitive workflows. Their ability to act also makes permissions, supervision, and clear stopping conditions important.", firstStep: "Map a simple task into steps, and mark where a person should review before anything is sent or changed.", watchFor: "An agent may misunderstand a request or repeat an incorrect action. Start with limited permissions and require approval for consequential changes.", icon: Bot, color: "blue", level: "Emerging" },
  { title: "Prompting that works", category: "AI & models", description: "Write instructions with clear goals, constraints, examples, and an audience in mind.", takeaway: "Treat prompts as briefs: provide context, define success, and iterate based on what is missing.", whyItMatters: "A well-framed request reduces guesswork and makes responses easier to evaluate. Prompting is an iterative communication skill, not a collection of secret phrases.", firstStep: "Rewrite a vague request by adding a role, audience, format, and one example.", watchFor: "More words do not always mean better results. Remove irrelevant details, and never assume a carefully written prompt guarantees factual accuracy.", icon: Lightbulb, color: "amber", level: "Practical" },
  { title: "AI safety & privacy", category: "AI & models", description: "Learn to check outputs, protect sensitive data, and notice limitations before relying on AI.", takeaway: "Use the least sensitive information possible and independently check high-impact or factual decisions.", whyItMatters: "AI systems can affect decisions, expose information, or produce biased and inaccurate outputs. Basic privacy habits and human review help reduce avoidable risk.", firstStep: "Make a quick checklist for what you would never paste into a public AI tool.", watchFor: "Do not upload confidential, personal, or regulated information without authorization. Treat high-impact advice as something to verify with qualified sources.", icon: ShieldCheck, color: "green", level: "Essential" },
  { title: "AI models & context", category: "AI & models", description: "Learn what context windows, tokens, and retrieval mean in everyday AI products.", takeaway: "A model can only work with information available in its context or connected sources; more context is not always better.", whyItMatters: "Context determines what an assistant can consider in a response. Understanding retrieval and context limits helps you provide relevant material and recognize when a system may not have seen a key detail.", firstStep: "Ask an assistant to answer from a supplied note only and identify what the note does not say.", watchFor: "A long conversation can exceed a model's usable context, and retrieved passages can be incomplete. Ask what sources informed an answer and check them directly.", icon: Atom, color: "pink", level: "Core concept" },
  { title: "Machine learning basics", category: "AI & models", description: "See how examples, training, evaluation, and feedback fit into a machine-learning system.", takeaway: "A model that performs well on practice examples may still fail on new or unbalanced data.", whyItMatters: "Machine learning powers recommendations, predictions, and classification tools. Understanding training data and evaluation makes it easier to judge whether a model is appropriate for a real task.", firstStep: "Pick a simple prediction task and list what a representative dataset would need to include.", watchFor: "Biased or outdated examples can produce unreliable results. Test performance on data the model did not train on and consider who may be affected by errors.", icon: Workflow, color: "teal", level: "Core concept" },
  { title: "AI for research", category: "AI & models", description: "Use AI to organize questions and summarize sources while keeping evidence traceable.", takeaway: "A summary is a starting point, not a substitute for checking the original source and its date.", whyItMatters: "AI can help turn a broad subject into focused questions and make large reading lists more manageable. Keeping links and quotations attached to claims makes your research easier to trust and revisit.", firstStep: "Ask for a source-by-source summary and verify one important quotation in the original.", watchFor: "Generated citations may be inaccurate or nonexistent. Open the original publication, check its date and methodology, and separate evidence from interpretation.", icon: BookOpen, color: "blue", level: "Study skill" },
  { title: "AI coding assistants", category: "Build & code", description: "Use coding tools to understand unfamiliar code, draft tests, and explore implementation options.", takeaway: "Review generated changes as carefully as a teammate’s code: test them, check assumptions, and understand the diff.", whyItMatters: "Coding assistants can reduce setup work and help explain unfamiliar patterns, letting you spend more time understanding the problem. They are most effective when you give them a small, well-defined task and keep control of the changes.", firstStep: "Ask an assistant to explain a small function before asking it to change anything.", watchFor: "Generated code may be insecure, incorrect, or inconsistent with the project. Run relevant tests and review every changed file before accepting it.", icon: Code2, color: "purple", level: "Developer tools" },
  { title: "Git & GitHub", category: "Build & code", description: "Track code changes, collaborate safely, and keep a useful history of your projects.", takeaway: "Small commits and readable pull requests make it easier to understand, review, and undo changes.", whyItMatters: "Version control gives you a reliable record of how a project changes and a way for people to work together. Git tracks the history; GitHub adds a hosted place to share repositories and review contributions.", firstStep: "Create a tiny practice repo and make one commit for each meaningful change.", watchFor: "A commit is not automatically a backup if it exists only on your device. Never commit passwords or API keys, and inspect what you are sharing before pushing.", icon: GitBranch, color: "orange", level: "Developer tools" },
  { title: "Build a first website", category: "Build & code", description: "Learn how pages, components, styling, and deployment fit together in a web project.", takeaway: "Start with one clear user goal; build a small working path before adding extra features.", whyItMatters: "A small website project brings together design, content, code, and publishing in a visible way. Finishing a simple version teaches more than planning a large app that never gets built.", firstStep: "Sketch a one-page idea with a headline, one main action, and three useful content blocks.", watchFor: "A page that looks good on one screen may not work well on a phone or with a keyboard. Check responsive layouts, readable contrast, and accessible labels early.", icon: Zap, color: "amber", level: "Project idea" },
  { title: "Automation workflows", category: "Build & code", description: "Connect routine tasks with clear triggers, checks, and human review when needed.", takeaway: "Automation works best when its inputs, failure cases, and approval points are designed up front.", whyItMatters: "Well-designed workflows make repeatable tasks more consistent and free people to focus on work that needs judgment. A clear process also makes it easier to spot where delays or mistakes occur.", firstStep: "Write down a repetitive task and identify its trigger, steps, and one condition that requires review.", watchFor: "Automating a broken process can make its problems happen faster. Plan for missing data, failed steps, duplicate actions, and a safe way to pause the workflow.", icon: Workflow, color: "green", level: "Productivity" },
  { title: "Cloud computing", category: "Build & code", description: "Explore how hosted compute, storage, and managed services power modern applications.", takeaway: "Cloud services trade upfront infrastructure for on-demand resources that still need secure configuration.", whyItMatters: "Cloud platforms let teams launch applications without owning every server themselves and scale resources as needs change. Understanding the basic pieces helps you make sensible decisions about cost, reliability, and access.", firstStep: "Draw the path from a browser request to an app server, database, and stored file.", watchFor: "Cloud resources can be exposed or become unexpectedly expensive when configured poorly. Use least-privilege access, monitor usage, and know where data is stored.", icon: Compass, color: "teal", level: "Technology" },
  { title: "Dropshipping basics", category: "Business", description: "Understand supplier fulfillment, customer expectations, costs, returns, and operational trade-offs.", takeaway: "The seller remains responsible for the customer experience even when a supplier ships the order.", whyItMatters: "Dropshipping changes who stores and sends inventory, but it does not remove the work of choosing products, setting expectations, supporting customers, or managing returns. Understanding the model helps you assess whether the trade-offs fit a real business plan.", firstStep: "Build a sample unit-economics sheet with product cost, shipping, fees, returns, and marketing.", watchFor: "Long delivery times, inconsistent quality, thin margins, and unclear return terms can damage trust. Verify suppliers and calculate the full cost before making promises or spending on ads.", icon: ShoppingBag, color: "blue", level: "Business guide" },
  { title: "AI in e-commerce", category: "Business", description: "Explore careful uses of AI for product research, support drafts, and creative experiments.", takeaway: "AI can speed up research and drafts, but product claims, customer data, and final decisions need human checks.", whyItMatters: "AI can help small teams explore ideas and prepare routine content more quickly. Used thoughtfully, it can support experimentation while people stay accountable for accurate product information and respectful customer service.", firstStep: "Draft two product descriptions and compare each claim with the supplier’s verified details.", watchFor: "Do not let generated copy invent product benefits, delivery promises, or reviews. Protect customer information and check advertising and consumer-protection rules for your market.", icon: Sparkles, color: "purple", level: "AI + business" },
  { title: "Starting an online store", category: "Business", description: "Get familiar with storefronts, product pages, checkout, fulfillment, and customer support.", takeaway: "A reliable store depends on trust: accurate information, clear delivery expectations, and straightforward returns.", whyItMatters: "An online store is a complete customer journey, not just a catalog. Product details, payment, delivery, and support all shape whether customers feel confident buying and coming back.", firstStep: "Review a product page and note the questions a customer needs answered before buying.", watchFor: "Hidden costs, vague shipping timelines, inaccessible checkout, or hard-to-find return policies can erode trust. Test the full experience on mobile before launch.", icon: ShoppingBag, color: "orange", level: "E-commerce" },
  { title: "Digital marketing", category: "Business", description: "Learn the basics of audience research, helpful content, channels, and measurement.", takeaway: "Good marketing starts with understanding a real audience problem and testing a useful message.", whyItMatters: "Digital channels help businesses reach people where they already spend time and learn from measurable responses. A focused strategy makes it easier to understand which messages and channels are actually useful.", firstStep: "Describe one audience, one problem they have, and one useful piece of content you could make.", watchFor: "Views and clicks do not always translate to meaningful outcomes. Use privacy-conscious measurement, avoid misleading claims, and judge campaigns against clear goals.", icon: LineChart, color: "green", level: "Business skill" },
  { title: "Critical thinking with AI", category: "Skills", description: "Use questions, evidence, and comparison to make better decisions with AI-generated answers.", takeaway: "Ask what evidence supports an answer, what might be missing, and what would change the conclusion.", whyItMatters: "AI can make it easier to explore ideas, but it can also reinforce assumptions or present weak evidence persuasively. Critical thinking helps you use it to widen your view rather than outsource your judgment.", firstStep: "Take an AI answer and write down one supporting source and one plausible counterpoint.", watchFor: "A confident tone is not evidence. Look for original sources, alternative explanations, and missing perspectives—especially before important decisions.", icon: BrainCircuit, color: "pink", level: "Essential skill" },
  { title: "Learning how to learn", category: "Skills", description: "Build a sustainable learning loop with small goals, active recall, and reflection.", takeaway: "Retrieving knowledge from memory is often more effective than rereading the same notes repeatedly.", whyItMatters: "A few dependable study habits help you retain information and apply it beyond a single lesson. Setting small goals and revisiting ideas over time makes learning easier to sustain.", firstStep: "After a short lesson, close it and write three things you remember before checking your notes.", watchFor: "Rereading can feel productive without showing what you can recall. Use practice questions, space review sessions out, and make room for rest.", icon: BookOpen, color: "amber", level: "Study skill" },
  { title: "Communication & teamwork", category: "Skills", description: "Practice explaining ideas clearly, sharing progress, and working well with different people.", takeaway: "Clear updates explain what changed, what is blocked, and what happens next.", whyItMatters: "Most meaningful projects depend on coordination. Listening carefully, making expectations explicit, and sharing timely updates help teams solve problems before they become bigger blockers.", firstStep: "Turn a recent task into a three-line update: completed, current blocker, next action.", watchFor: "People may interpret the same message differently. Confirm decisions in writing, invite questions, and adapt your communication style to the audience.", icon: BriefcaseBusiness, color: "teal", level: "Career skill" },
]

const learningPaths = [
  { number: "01", title: "Understand AI", text: "Start with generative AI, prompting, and the limits worth knowing.", links: ["Generative AI", "Prompting that works", "AI safety & privacy"], color: "from-violet-600 to-indigo-500" },
  { number: "02", title: "Build something", text: "Move from coding tools to a first project and a shareable result.", links: ["AI coding assistants", "Git & GitHub", "Build a first website"], color: "from-cyan-600 to-blue-500" },
  { number: "03", title: "Explore business", text: "Learn the mechanics behind e-commerce before spending money.", links: ["Dropshipping basics", "AI in e-commerce", "Digital marketing"], color: "from-orange-500 to-rose-500" },
]

const resources = [
  { title: "GitHub", text: "Store projects and collaborate on code.", href: "/github", icon: Github, color: "blue" },
  { title: "Git", text: "Track changes and build a useful history.", href: "/git", icon: GitBranch, color: "orange" },
  { title: "v0 Templates", text: "Explore AI-assisted ways to start building.", href: "/v0-templates", icon: Zap, color: "purple" },
  { title: "NotebookLM", text: "Organize sources and study with AI.", href: "/notebooklm", icon: BookOpen, color: "green" },
]

function TopicCard({ topic }: { topic: Topic }) {
  const Icon = topic.icon
  return (
    <article className="topic-card group flex flex-col rounded-2xl border border-border bg-card p-5 transition duration-200 hover:-translate-y-1 hover:border-primary/30 hover:shadow-[0_18px_45px_-28px_rgba(29,39,71,.36)] sm:p-6">
      <div className="mb-5 flex items-center justify-between gap-3">
        <span className={`topic-icon topic-icon-${topic.color} grid size-11 place-items-center rounded-xl`}><Icon aria-hidden="true" size={21} /></span>
        <span className="rounded-full bg-muted px-3 py-1 text-[11px] font-medium text-muted-foreground">{topic.level}</span>
      </div>
      <p className="text-xs font-medium uppercase tracking-[.12em] text-primary/75">{topic.category}</p>
      <h3 className="mt-2 text-lg font-semibold tracking-tight text-foreground">{topic.title}</h3>
      <p className="mt-2 flex-1 text-sm leading-6 text-muted-foreground">{topic.description}</p>
      <details className="topic-details mt-5 border-t border-border pt-4">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-sm font-semibold text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          Explore full guide <ChevronDown className="size-4 transition-transform" aria-hidden="true" />
        </summary>
        <div className="mt-4 flex flex-col gap-4 text-sm leading-6 text-foreground/80">
          <div><p className="text-xs font-semibold uppercase tracking-[.12em] text-primary/75">Core idea</p><p className="mt-1">{topic.takeaway}</p></div>
          <div><p className="text-xs font-semibold uppercase tracking-[.12em] text-primary/75">Why it matters</p><p className="mt-1">{topic.whyItMatters}</p></div>
          <p className="rounded-xl bg-muted p-4"><strong className="font-semibold text-foreground">Try this:</strong> {topic.firstStep}</p>
          <div><p className="text-xs font-semibold uppercase tracking-[.12em] text-primary/75">Watch for</p><p className="mt-1">{topic.watchFor}</p></div>
        </div>
      </details>
    </article>
  )
}

export function LearningHub() {
  const [query, setQuery] = useState("")
  const [activeCategory, setActiveCategory] = useState<Category>("All topics")
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const visibleTopics = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    return topics.filter((topic) => {
      const matchesCategory = activeCategory === "All topics" || topic.category === activeCategory
      const matchesQuery = !normalizedQuery || `${topic.title} ${topic.category} ${topic.description} ${topic.takeaway}`.toLowerCase().includes(normalizedQuery)
      return matchesCategory && matchesQuery
    })
  }, [activeCategory, query])

  return (
    <main id="home" className="min-h-screen overflow-hidden bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-y-3 px-5 py-4 sm:px-8">
          <Link href="#home" className="flex items-center gap-3" aria-label="LearnLab home">
            <span className="grid size-10 place-items-center rounded-xl bg-primary text-primary-foreground"><BrainCircuit size={21} aria-hidden="true" /></span>
            <span><span className="block text-base font-bold tracking-tight">LearnLab</span><span className="block text-[10px] font-medium uppercase tracking-[.18em] text-muted-foreground">Ideas into action</span></span>
          </Link>
          <button type="button" className="grid size-10 place-items-center rounded-xl border border-border text-foreground md:hidden" aria-label={mobileMenuOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileMenuOpen} onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
            {mobileMenuOpen ? <X size={19} /> : <Menu size={19} />}
          </button>
          <nav aria-label="Main navigation" className={`${mobileMenuOpen ? "flex" : "hidden"} order-3 w-full flex-col gap-1 rounded-2xl border border-border bg-card p-2 text-sm font-medium text-muted-foreground md:order-none md:flex md:w-auto md:flex-row md:items-center md:gap-2 md:border-0 md:bg-transparent md:p-0`}>
            <a href="#paths" onClick={() => setMobileMenuOpen(false)} className="rounded-xl px-4 py-2.5 transition hover:bg-muted hover:text-foreground">Learning paths</a>
            <a href="#topics" onClick={() => setMobileMenuOpen(false)} className="rounded-xl px-4 py-2.5 transition hover:bg-muted hover:text-foreground">Explore topics</a>
            <a href="#tools" onClick={() => setMobileMenuOpen(false)} className="rounded-xl px-4 py-2.5 transition hover:bg-muted hover:text-foreground">Tool guides</a>
          </nav>
          <a href="#topics" className="hidden items-center gap-2 rounded-full bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition hover:bg-primary/90 sm:inline-flex">Start exploring <ArrowUpRight size={15} aria-hidden="true" /></a>
        </div>
      </header>

      <section className="relative mx-auto grid max-w-7xl gap-12 px-5 pb-16 pt-16 sm:px-8 sm:pb-20 sm:pt-24 lg:grid-cols-[1.08fr_.92fr] lg:items-center lg:gap-16 lg:pt-28">
        <div className="absolute -right-32 -top-28 -z-0 size-[31rem] rounded-full border border-primary/10" aria-hidden="true" />
        <div className="relative z-10">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/15 bg-card px-3.5 py-2 text-xs font-semibold text-primary"><span className="size-2 rounded-full bg-accent" /> A curious mind&apos;s field guide</div>
          <h1 className="mt-7 max-w-3xl text-5xl font-semibold leading-[1.02] tracking-[-.055em] sm:text-6xl lg:text-7xl">Learn what&apos;s next. <span className="font-serif italic text-accent-foreground">Build what matters.</span></h1>
          <p className="mt-6 max-w-xl text-base leading-7 text-muted-foreground sm:text-lg sm:leading-8">Go beyond the basics with practical, approachable guides to AI, technology, online business, and the skills that help you keep growing.</p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a href="#topics" className="inline-flex items-center gap-2 rounded-full bg-primary px-5 py-3 text-sm font-semibold text-primary-foreground transition hover:bg-primary/90">Explore the library <ArrowRight size={16} aria-hidden="true" /></a>
            <a href="#paths" className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-5 py-3 text-sm font-semibold text-foreground transition hover:bg-muted">Choose a learning path <ArrowDownRight size={16} aria-hidden="true" /></a>
          </div>
          <div className="mt-9 flex flex-wrap gap-x-7 gap-y-2 text-sm text-muted-foreground"><span><strong className="text-foreground">20</strong> in-depth guides</span><span><strong className="text-foreground">4</strong> learning lanes</span><span><strong className="text-foreground">Practical</strong> first steps</span></div>
        </div>

        <aside className="relative z-10 rounded-[1.75rem] bg-primary p-6 text-primary-foreground shadow-[0_30px_90px_-45px_rgba(39,47,88,.65)] sm:p-8" aria-label="A simple learning loop">
          <div className="flex items-start justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-[.2em] text-primary-foreground/65">Your learning loop</p><h2 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">Small steps. Real momentum.</h2></div><span className="grid size-12 shrink-0 place-items-center rounded-2xl bg-primary-foreground/10 text-accent"><Compass size={22} aria-hidden="true" /></span></div>
          <p className="mt-4 max-w-md text-sm leading-6 text-primary-foreground/75">Pick a question, learn one useful idea, then try it in a small project. Come back when you&apos;re ready for the next step.</p>
          <ol className="mt-7 flex flex-col gap-3">
            {["Choose a topic that sparks your curiosity", "Explore a guide and learn its key ideas", "Try the suggested first step for yourself"].map((step, index) => <li key={step} className="flex items-center gap-3 rounded-xl border border-primary-foreground/10 bg-primary-foreground/[.06] p-3.5"><span className="grid size-8 shrink-0 place-items-center rounded-full bg-accent text-xs font-bold text-accent-foreground">0{index + 1}</span><span className="text-sm font-medium">{step}</span><Check size={15} className="ml-auto shrink-0 text-primary-foreground/45" aria-hidden="true" /></li>)}
          </ol>
          <div className="mt-7 flex items-center justify-between border-t border-primary-foreground/15 pt-5 text-xs text-primary-foreground/65"><span>Curiosity is a great place to start.</span><BookOpen size={17} aria-hidden="true" /></div>
        </aside>
      </section>

      <section id="paths" className="border-y border-border bg-card/70">
        <div className="mx-auto max-w-7xl px-5 py-14 sm:px-8 sm:py-16">
          <div className="mb-8 flex flex-wrap items-end justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[.18em] text-primary/70">Pick your direction</p><h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Three ways to get started.</h2></div><p className="max-w-md text-sm leading-6 text-muted-foreground">No perfect order required. Follow the path that feels useful today.</p></div>
          <div className="grid gap-4 md:grid-cols-3">
            {learningPaths.map((path) => <article key={path.number} className="relative overflow-hidden rounded-2xl border border-border bg-background p-6 transition hover:-translate-y-1 hover:shadow-lg"><div className={`absolute inset-x-0 top-0 h-1 bg-gradient-to-r ${path.color}`} /><div className="flex items-center justify-between"><span className="font-mono text-xs text-muted-foreground">PATH / {path.number}</span><ArrowUpRight size={17} className="text-muted-foreground" aria-hidden="true" /></div><h3 className="mt-7 text-xl font-semibold tracking-tight">{path.title}</h3><p className="mt-2 min-h-12 text-sm leading-6 text-muted-foreground">{path.text}</p><div className="mt-5 flex flex-wrap gap-2">{path.links.map((link) => <a href="#topics" key={link} onClick={() => { setActiveCategory(link.includes("Dropshipping") || link.includes("e-commerce") || link.includes("marketing") ? "Business" : link.includes("Git") || link.includes("coding") || link.includes("website") ? "Build & code" : "AI & models"); setQuery("") }} className="rounded-full bg-muted px-3 py-1.5 text-xs font-medium text-foreground/75 transition hover:bg-primary/10 hover:text-primary">{link}</a>)}</div></article>)}
          </div>
        </div>
      </section>

      <section id="topics" className="mx-auto max-w-7xl scroll-mt-24 px-5 py-16 sm:px-8 sm:py-20">
        <div className="flex flex-col gap-7 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl"><p className="text-xs font-bold uppercase tracking-[.18em] text-primary/70">The idea library</p><h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Explore a guide. Make it useful.</h2><p className="mt-3 text-base leading-7 text-muted-foreground">Detailed, approachable guides—with clear explanations, key ideas, practical first steps, and common pitfalls.</p></div>
          <label className="flex w-full items-center gap-3 rounded-full border border-border bg-card px-4 py-3 text-muted-foreground shadow-sm transition focus-within:border-primary/40 focus-within:ring-2 focus-within:ring-primary/10 lg:max-w-sm"><Search size={18} aria-hidden="true" /><span className="sr-only">Search learning guides</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search AI, Claude, e-commerce..." className="w-full bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground" /></label>
        </div>
        <div className="mt-7 flex gap-2 overflow-x-auto pb-2" role="group" aria-label="Filter guides by category">
          {categories.map((category) => <button key={category} type="button" onClick={() => setActiveCategory(category)} aria-pressed={activeCategory === category} className={`shrink-0 rounded-full border px-4 py-2 text-sm font-medium transition ${activeCategory === category ? "border-primary bg-primary text-primary-foreground" : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:text-foreground"}`}>{category}</button>)}
        </div>
        <p className="mt-4 text-xs text-muted-foreground" aria-live="polite">Showing {visibleTopics.length} {visibleTopics.length === 1 ? "guide" : "guides"}</p>
        {visibleTopics.length > 0 ? <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">{visibleTopics.map((topic) => <TopicCard key={topic.title} topic={topic} />)}</div> : <div className="mt-4 rounded-2xl border border-dashed border-border bg-card p-10 text-center"><p className="font-semibold">No guides found</p><p className="mt-2 text-sm text-muted-foreground">Try another search or choose a different category.</p><button type="button" onClick={() => { setQuery(""); setActiveCategory("All topics") }} className="mt-4 text-sm font-semibold text-primary underline underline-offset-4">Clear filters</button></div>}
      </section>

      <section id="tools" className="border-y border-border bg-card/70">
        <div className="mx-auto max-w-7xl px-5 py-14 sm:px-8 sm:py-16">
          <div className="mb-8 flex flex-wrap items-end justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[.18em] text-primary/70">Go a little deeper</p><h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Guides to useful tools.</h2></div><Link href="/notebooklm" className="inline-flex items-center gap-2 text-sm font-semibold text-primary hover:underline">Open NotebookLM guide <ArrowRight size={15} aria-hidden="true" /></Link></div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">{resources.map((resource) => { const Icon = resource.icon; return <Link key={resource.title} href={resource.href} className="group rounded-2xl border border-border bg-background p-5 transition hover:-translate-y-1 hover:border-primary/30 hover:shadow-lg"><div className={`topic-icon topic-icon-${resource.color} grid size-11 place-items-center rounded-xl`}><Icon size={20} aria-hidden="true" /></div><h3 className="mt-5 text-lg font-semibold tracking-tight">{resource.title}</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">{resource.text}</p><span className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-primary">Explore guide <ArrowRight size={14} aria-hidden="true" className="transition-transform group-hover:translate-x-1" /></span></Link>})}</div>
        </div>
      </section>

      <footer className="mx-auto flex max-w-7xl flex-col gap-5 px-5 py-8 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-8"><Link href="#home" className="flex items-center gap-2 font-semibold text-foreground"><span className="grid size-8 place-items-center rounded-lg bg-primary text-primary-foreground"><BrainCircuit size={17} aria-hidden="true" /></span> LearnLab</Link><p>Keep learning. Keep asking better questions.</p><a href="#home" className="inline-flex items-center gap-1 hover:text-foreground">Back to top <ArrowUpRight size={14} aria-hidden="true" /></a></footer>
    </main>
  )
}
