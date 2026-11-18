import Link from "next/link"
import {
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Check,
  GitBranch,
  Github,
  Layers3,
  Lightbulb,
  ShieldCheck,
  Zap,
} from "lucide-react"

const tools = [
  {
    id: "github",
    name: "GitHub",
    category: "Collaboration platform",
    description: "GitHub hosts Git repositories online and gives individuals and teams a shared place to review code, track work, and maintain projects.",
    bestFor: "Sharing projects, working with teammates, and keeping a searchable home for your code and documentation.",
    icon: Github,
    color: "blue",
    link: "/github",
    actions: [
      "Store repositories remotely and control who can access them.",
      "Propose and review changes with branches and pull requests.",
      "Organize work with issues, discussions, and project boards.",
    ],
    firstStep: "Create a repository for a small project, add a clear description, and invite a collaborator to review a change.",
    watchFor: "GitHub is not Git itself. A remote repository is useful for sharing and backup, but protect credentials and review access before making a project public.",
  },
  {
    id: "git",
    name: "Git",
    category: "Version control",
    description: "Git is a distributed version-control system that records changes to files as a project develops. Its history lives with your local repository, so you can work and create commits offline.",
    bestFor: "Saving meaningful checkpoints, experimenting on separate branches, and understanding how a project changed over time.",
    icon: GitBranch,
    color: "orange",
    link: "/git",
    actions: [
      "Stage selected changes and save them as descriptive commits.",
      "Create branches to work on a feature without disturbing the main line.",
      "Compare versions, combine work, and recover from many mistakes.",
    ],
    firstStep: "Initialize a practice project, make one small edit, then commit it with a message that explains the change.",
    watchFor: "A commit is a local history checkpoint, not automatically an online backup. Review what you stage, write focused commits, and never commit passwords or API keys.",
  },
  {
    id: "v0-templates",
    name: "v0 Templates",
    category: "AI-assisted building",
    description: "v0 helps turn product ideas, prompts, and design references into web interfaces. Templates give you a starting structure you can adapt, preview, and refine for your own project.",
    bestFor: "Exploring a UI direction quickly, starting a Next.js project, and iterating on components and page layouts.",
    icon: Zap,
    color: "purple",
    link: "/v0-templates",
    actions: [
      "Start from a working page or interface instead of a blank canvas.",
      "Describe changes in plain language and refine the result in steps.",
      "Use generated components as a foundation for a more complete app.",
    ],
    firstStep: "Describe who the page is for, what they need to do, and the three most important pieces of information it should show.",
    watchFor: "Generated UI still needs review. Check mobile layouts, keyboard accessibility, content accuracy, and whether any integrations or data handling are configured safely.",
  },
  {
    id: "notebooklm",
    name: "NotebookLM",
    category: "Research & study",
    description: "NotebookLM helps you work with a collection of sources. Add materials to a notebook, ask questions grounded in those sources, and use the responses to guide your reading and study.",
    bestFor: "Making a large set of class notes, documents, or research sources easier to explore and understand.",
    icon: BookOpen,
    color: "green",
    link: "/notebooklm",
    actions: [
      "Keep related source materials together in focused notebooks.",
      "Ask questions and follow references back to the supporting material.",
      "Create summaries and study prompts from the sources you provide.",
    ],
    firstStep: "Add a small set of trusted course or project sources, then ask a focused question and open the cited passages to verify the answer.",
    watchFor: "Answers depend on the sources you add and may omit important context. Check cited passages yourself and review privacy settings before uploading sensitive documents.",
  },
]

const workflowTools = [tools[3], tools[2], tools[1], tools[0]]

function ToolCard({ tool }: { tool: (typeof tools)[number] }) {
  const Icon = tool.icon

  return (
    <article id={tool.id} className="scroll-mt-28 rounded-[1.5rem] border border-border bg-card p-6 shadow-sm transition duration-200 hover:-translate-y-1 hover:border-primary/25 hover:shadow-[0_24px_60px_-38px_rgba(29,39,71,.42)] sm:p-8">
      <div className="flex items-start justify-between gap-4">
        <span className={`topic-icon topic-icon-${tool.color} grid size-14 shrink-0 place-items-center rounded-2xl`}>
          <Icon aria-hidden="true" size={25} />
        </span>
        <span className="rounded-full bg-muted px-3 py-1.5 text-xs font-medium text-muted-foreground">{tool.category}</span>
      </div>
      <h2 className="mt-6 text-2xl font-semibold tracking-tight text-foreground">{tool.name}</h2>
      <p className="mt-3 text-sm leading-7 text-muted-foreground sm:text-base">{tool.description}</p>
      <div className="mt-5 rounded-xl border border-border/80 bg-background p-4">
        <p className="text-xs font-semibold uppercase tracking-[.14em] text-primary/75">Best for</p>
        <p className="mt-1.5 text-sm leading-6 text-foreground/80">{tool.bestFor}</p>
      </div>
      <div className="mt-6">
        <h3 className="text-sm font-semibold text-foreground">What you can do</h3>
        <ul className="mt-3 flex flex-col gap-2.5">
          {tool.actions.map((action) => (
            <li key={action} className="flex gap-2.5 text-sm leading-6 text-muted-foreground">
              <Check aria-hidden="true" size={16} className="mt-1 shrink-0 text-primary" />
              <span>{action}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-6 rounded-xl bg-muted/80 p-4">
        <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[.14em] text-primary/75"><Lightbulb aria-hidden="true" size={14} /> Try this first</p>
        <p className="mt-2 text-sm leading-6 text-foreground/80">{tool.firstStep}</p>
      </div>
      <div className="mt-4 flex gap-2.5 rounded-xl border border-border/80 p-4">
        <ShieldCheck aria-hidden="true" size={17} className="mt-0.5 shrink-0 text-muted-foreground" />
        <p className="text-xs leading-5 text-muted-foreground"><span className="font-semibold text-foreground">Keep in mind: </span>{tool.watchFor}</p>
      </div>
      <Link href={tool.link} className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-primary transition hover:gap-3 focus-visible:rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        Explore the full guide <ArrowRight aria-hidden="true" size={16} />
      </Link>
    </article>
  )
}

export function LearningHub() {
  return (
    <main id="home" className="min-h-screen overflow-hidden bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/80 bg-background/90 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-5 py-4 sm:px-8">
          <Link href="#home" className="flex items-center gap-3" aria-label="LearnLab home">
            <span className="grid size-10 place-items-center rounded-xl bg-primary text-primary-foreground"><Layers3 aria-hidden="true" size={20} /></span>
            <span><span className="block text-base font-bold tracking-tight">LearnLab</span><span className="block text-[10px] font-medium uppercase tracking-[.18em] text-muted-foreground">Essential tool guides</span></span>
          </Link>
          <nav aria-label="Tool guides" className="flex max-w-full flex-wrap items-center justify-end gap-1 text-sm font-medium text-muted-foreground sm:gap-2">
            {tools.map((tool) => <a key={tool.id} href={`#${tool.id}`} className="rounded-full px-3 py-2 transition hover:bg-muted hover:text-foreground">{tool.name}</a>)}
          </nav>
        </div>
      </header>

      <section className="relative mx-auto max-w-7xl px-5 pb-12 pt-16 sm:px-8 sm:pb-16 sm:pt-24">
        <div className="absolute -right-32 -top-28 -z-0 size-[31rem] rounded-full border border-primary/10" aria-hidden="true" />
        <div className="relative z-10 max-w-3xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-primary/15 bg-card px-3.5 py-2 text-xs font-semibold text-primary"><span className="size-2 rounded-full bg-accent" /> Four tools. One stronger workflow.</div>
          <h1 className="mt-7 text-5xl font-semibold leading-[1.03] tracking-[-.055em] sm:text-6xl">Learn the tools. <span className="font-serif italic text-primary">Make ideas real.</span></h1>
          <p className="mt-6 max-w-2xl text-base leading-7 text-muted-foreground sm:text-lg sm:leading-8">A practical guide to GitHub, Git, v0 Templates, and NotebookLM—what each one does, when it helps, and how to take your first step.</p>
          <div className="mt-7 flex flex-wrap items-center gap-x-7 gap-y-2 text-sm text-muted-foreground"><span><strong className="text-foreground">4</strong> focused guides</span><span><strong className="text-foreground">3</strong> practical actions each</span><span><strong className="text-foreground">1</strong> connected workflow</span></div>
        </div>
      </section>

      <section aria-label="The four tool guides" className="mx-auto max-w-7xl px-5 pb-16 sm:px-8 sm:pb-20">
        <div className="grid gap-5 lg:grid-cols-2 lg:gap-6">
          {tools.map((tool) => <ToolCard key={tool.id} tool={tool} />)}
        </div>
      </section>

      <section className="border-y border-border bg-card/70" aria-labelledby="workflow-heading">
        <div className="mx-auto max-w-7xl px-5 py-12 sm:px-8 sm:py-14">
          <div className="flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
            <div><p className="text-xs font-bold uppercase tracking-[.18em] text-primary/70">How they fit together</p><h2 id="workflow-heading" className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">From first idea to shared project.</h2></div>
            <p className="max-w-xl text-sm leading-6 text-muted-foreground">Research with NotebookLM, shape the interface in v0, track your work with Git, then share and review it on GitHub.</p>
          </div>
          <ol className="mt-7 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {workflowTools.map((tool, index) => { const Icon = tool.icon; return <li key={tool.id} className="flex items-center gap-3 rounded-xl border border-border bg-background p-4"><span className={`topic-icon topic-icon-${tool.color} grid size-10 shrink-0 place-items-center rounded-xl`}><Icon aria-hidden="true" size={19} /></span><span><span className="block text-[10px] font-medium uppercase tracking-[.14em] text-muted-foreground">Step 0{index + 1}</span><span className="mt-0.5 block text-sm font-semibold text-foreground">{tool.name}</span></span>{index < tools.length - 1 && <ArrowUpRight aria-hidden="true" size={15} className="ml-auto text-muted-foreground" />}</li>})}
          </ol>
        </div>
      </section>

      <footer className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-7 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-8"><Link href="#home" className="font-semibold text-foreground">LearnLab</Link><p>Four tools to help you build, learn, and collaborate.</p><a href="#home" className="font-medium transition hover:text-foreground">Back to top</a></footer>
    </main>
  )
}
