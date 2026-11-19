import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  Cloud,
  Github,
  GraduationCap,
  Linkedin,
  Mail,
  MapPin,
  Network,
  Phone,
  ShieldCheck,
  Terminal,
  type LucideIcon,
} from "lucide-react"

const experience = [
  "Secured AWS and Azure environments by configuring IAM permissions, protecting credentials with Secrets Manager, and limiting database access with firewall rules.",
  "Implemented multi-factor authentication with AWS Cognito and protected API connections using API Gateway and mutual TLS certificates.",
  "Built CloudWatch dashboards and alerts to bring security events into view for faster investigation.",
  "Supported vulnerability testing and threat research with AI-assisted tools, collaborating in an Agile team to apply security best practices.",
]

const skillGroups = [
  {
    number: "01",
    title: "Security operations",
    icon: ShieldCheck,
    items: "Security monitoring · Alerts · Firewalls · IDS/IPS · Vulnerability assessment · Incident detection",
  },
  {
    number: "02",
    title: "Cloud security",
    icon: Cloud,
    items: "AWS IAM · Cognito · CloudWatch · Secrets Manager · API Gateway · RDS · Azure fundamentals",
  },
  {
    number: "03",
    title: "Identity & API security",
    icon: Network,
    items: "MFA · Access control · Least privilege · Certificate-based API security · mTLS",
  },
  {
    number: "04",
    title: "Networks & systems",
    icon: Terminal,
    items: "TCP/IP · DNS · LAN/WAN · Windows Server · Active Directory · Ubuntu Linux · Virtual machines",
  },
  {
    number: "05",
    title: "Web & development",
    icon: BookOpen,
    items: "Next.js · TypeScript · Supabase · Vercel · GitHub",
  },
]

const projects: {
  number: string
  eyebrow: string
  title: string
  description: string
  url: string
  action: string
  icon: LucideIcon
  tags: string[]
}[] = [
  {
    number: "01",
    eyebrow: "Controlled security lab",
    title: "Live Hacking Lab",
    description:
      "A hands-on environment for exploring common web threats and the controls that help detect or block them. I built scenarios around SQL injection, cross-site scripting, authentication bypass, and bot traffic, then added secure login, access controls, and activity logging.",
    url: "https://digital-twin-digitalmind222.vercel.app",
    action: "Explore the lab",
    icon: ShieldCheck,
    tags: ["Next.js", "TypeScript", "Supabase", "Defensive testing"],
  },
  {
    number: "02",
    eyebrow: "Learning project",
    title: "AI Study Assistant & Notes",
    description:
      "A companion learning site for keeping notes and study material close at hand, with an AI study assistant for exploring technical topics. It reflects how I use web tools to make learning more structured and easier to revisit.",
    url: "https://notes.ashminaryal.info",
    action: "Visit my notes site",
    icon: BookOpen,
    tags: ["AI-assisted study", "Technical learning", "Notes"],
  },
]

const externalLinkProps = {
  target: "_blank",
  rel: "noopener noreferrer",
} as const

function SectionHeading({
  index,
  eyebrow,
  title,
  description,
}: {
  index: string
  eyebrow: string
  title: string
  description?: string
}) {
  return (
    <div className="mb-10 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div>
        <p className="section-label"><span>{index}</span> / {eyebrow}</p>
        <h2 className="mt-4 max-w-3xl text-3xl font-semibold tracking-[-0.04em] text-[#f1f4ee] sm:text-4xl lg:text-5xl">{title}</h2>
      </div>
      {description ? <p className="max-w-md text-sm leading-6 text-[#a0aea5]">{description}</p> : null}
    </div>
  )
}

function SiteHeader() {
  return (
    <header className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-5 py-5 sm:px-8 lg:px-12">
      <a href="#home" className="group inline-flex items-center gap-3 rounded-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]" aria-label="Ashmin Aryal, home">
        <span className="grid size-10 place-items-center border border-[#34423b] bg-[#111a16] font-mono text-xs font-semibold text-[#c7f36a]">AA<span className="sr-only"> initials</span></span>
        <span className="flex flex-col gap-0.5">
          <span className="text-sm font-semibold tracking-[0.08em] text-[#f1f4ee]">ASHMIN ARYAL</span>
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#829087]">Cybersecurity student</span>
        </span>
      </a>

      <nav aria-label="Main navigation" className="order-3 flex w-full items-center gap-6 overflow-x-auto border-t border-[#25312b] pt-4 text-xs text-[#a0aea5] sm:order-none sm:w-auto sm:border-0 sm:pt-0 sm:text-sm">
        <a className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]" href="#about">About</a>
        <a className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]" href="#experience">Experience</a>
        <a className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]" href="#projects">Projects</a>
        <a className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]" href="#toolkit">Toolkit</a>
      </nav>

      <a href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com" {...externalLinkProps} className="inline-flex items-center gap-2 border border-[#405047] px-4 py-2.5 text-xs font-semibold text-[#f1f4ee] transition-colors hover:border-[#c7f36a] hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]">
        Get in touch <ArrowUpRight size={14} aria-hidden="true" />
      </a>
    </header>
  )
}

function FocusPanel() {
  const focusAreas = [
    { number: "01", label: "Cloud", detail: "AWS · Azure", icon: Cloud },
    { number: "02", label: "Identity", detail: "IAM · MFA · mTLS", icon: Network },
    { number: "03", label: "Visibility", detail: "Alerts · CloudWatch", icon: Terminal },
  ]

  return (
    <aside className="relative overflow-hidden border border-[#34423b] bg-[#101814]/90 p-5 shadow-[0_30px_100px_-55px_rgba(0,0,0,.9)] sm:p-7" aria-label="Cybersecurity areas of focus">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#c7f36a] to-transparent" aria-hidden="true" />
      <div className="flex items-center justify-between border-b border-[#27332d] pb-4">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#a0aea5]">Current focus</p>
        <span className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-[#c7f36a]"><span className="size-1.5 rounded-full bg-[#c7f36a]" /> Learning by doing</span>
      </div>
      <div className="mt-3">
        {focusAreas.map(({ number, label, detail, icon: Icon }) => (
          <div key={number} className="grid grid-cols-[2rem_2.25rem_1fr] items-center gap-3 border-b border-[#27332d] py-5 last:border-0">
            <span className="font-mono text-[10px] text-[#75847a]">{number}</span>
            <span className="grid size-9 place-items-center border border-[#34423b] bg-[#17211b] text-[#c7f36a]"><Icon size={16} aria-hidden="true" /></span>
            <div><p className="text-sm font-medium text-[#f1f4ee]">{label}</p><p className="mt-1 font-mono text-[10px] text-[#94a197]">{detail}</p></div>
          </div>
        ))}
      </div>
      <div className="mt-2 flex items-center justify-between border-t border-[#27332d] pt-4 font-mono text-[10px] uppercase tracking-[0.12em] text-[#829087]">
        <span>Study → build → defend</span><ShieldCheck size={15} className="text-[#c7f36a]" aria-hidden="true" />
      </div>
    </aside>
  )
}

function HeroSection() {
  return (
    <section id="home" className="relative mx-auto grid max-w-7xl gap-12 px-5 pb-16 pt-14 sm:px-8 sm:pb-20 sm:pt-20 lg:grid-cols-[1.25fr_.75fr] lg:items-center lg:px-12 lg:pb-24 lg:pt-24">
      <div className="pointer-events-none absolute inset-0 -z-10 portfolio-grid" aria-hidden="true" />
      <div className="pointer-events-none absolute -left-48 top-10 -z-10 size-[32rem] rounded-full bg-[#c7f36a]/[0.035] blur-3xl" aria-hidden="true" />
      <div>
        <div className="mb-8 flex flex-wrap items-center gap-x-3 gap-y-2 font-mono text-[10px] uppercase tracking-[0.18em] text-[#a0aea5] sm:text-xs">
          <span className="text-[#c7f36a]">Portfolio / 2026</span><span className="text-[#536158]">—</span><span className="inline-flex items-center gap-2"><MapPin size={12} aria-hidden="true" /> Sydney, Australia</span>
        </div>
        <h1 className="max-w-4xl text-[clamp(3rem,7.4vw,6.8rem)] font-semibold leading-[0.98] tracking-[-0.065em] text-[#f1f4ee]">
          Curious about systems.<br /><span className="text-[#c7f36a]">Focused on securing them.</span>
        </h1>
        <p className="mt-7 max-w-2xl text-base leading-7 text-[#b0bcb3] sm:text-lg sm:leading-8">
          I&apos;m Ashmin Aryal, a final-year Cyber Security student at Victoria University. I&apos;m building practical experience across cloud security, identity, and defensive monitoring—and looking for a cybersecurity or IT internship where I can keep learning and contribute.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <a href="#projects" className="inline-flex min-h-12 items-center gap-3 bg-[#c7f36a] px-5 text-sm font-semibold text-[#111811] transition-colors hover:bg-[#d8ff8c] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]">
            Explore my projects <ArrowDown size={16} aria-hidden="true" />
          </a>
          <a href="https://www.linkedin.com/in/ashmin-aryal-b42bab2a9" {...externalLinkProps} className="inline-flex min-h-12 items-center gap-3 border border-[#405047] px-5 text-sm font-semibold text-[#f1f4ee] transition-colors hover:border-[#c7f36a] hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]">
            Connect on LinkedIn <ArrowUpRight size={15} aria-hidden="true" />
          </a>
        </div>
        <div className="mt-10 flex flex-wrap gap-x-7 gap-y-3 border-t border-[#29352f] pt-5 font-mono text-[10px] uppercase tracking-[0.12em] text-[#89978d] sm:text-xs">
          <span><span className="text-[#c7f36a]">01</span> Cloud security</span>
          <span><span className="text-[#c7f36a]">02</span> Identity & access</span>
          <span><span className="text-[#c7f36a]">03</span> Security monitoring</span>
        </div>
      </div>
      <FocusPanel />
      <div className="grid grid-cols-3 border-y border-[#34423b] lg:col-span-2">
        <div className="py-4 pr-3 sm:py-5"><p className="font-mono text-xl font-medium tracking-tight text-[#f1f4ee] sm:text-2xl">10 weeks</p><p className="mt-1 text-[10px] uppercase tracking-[0.1em] text-[#89978d] sm:text-xs">Analyst internship</p></div>
        <div className="border-x border-[#34423b] px-3 py-4 sm:px-6 sm:py-5"><p className="font-mono text-xl font-medium tracking-tight text-[#f1f4ee] sm:text-2xl">2027</p><p className="mt-1 text-[10px] uppercase tracking-[0.1em] text-[#89978d] sm:text-xs">Degree expected</p></div>
        <div className="py-4 pl-3 sm:py-5 sm:pl-6"><p className="font-mono text-xl font-medium tracking-tight text-[#f1f4ee] sm:text-2xl">Hands-on</p><p className="mt-1 text-[10px] uppercase tracking-[0.1em] text-[#89978d] sm:text-xs">Defensive mindset</p></div>
      </div>
    </section>
  )
}

function AboutSection() {
  return (
    <section id="about" className="border-y border-[#26332c] bg-[#0d1411]">
      <div className="mx-auto grid max-w-7xl gap-10 px-5 py-16 sm:px-8 sm:py-20 lg:grid-cols-[.75fr_1.25fr] lg:gap-20 lg:px-12 lg:py-24">
        <div>
          <p className="section-label"><span>01</span> / About</p>
          <h2 className="mt-5 max-w-md text-3xl font-semibold leading-tight tracking-[-0.045em] text-[#f1f4ee] sm:text-4xl">Security starts with staying curious.</h2>
          <p className="mt-5 max-w-sm text-sm leading-6 text-[#a0aea5]">A student, a builder, and a careful learner—turning coursework into practical, defensive projects.</p>
        </div>
        <div>
          <p className="text-base leading-8 text-[#d0d8d1] sm:text-lg">
            I&apos;m completing a Bachelor of Cyber Security at Victoria University in Sydney. During a 10-week analyst internship and university security labs, I&apos;ve worked with cloud controls, identity and access, network defense, and vulnerability assessment.
          </p>
          <p className="mt-5 text-base leading-8 text-[#a0aea5] sm:text-lg">
            I created a live hacking lab to practice how common web threats work—and, more importantly, how application controls can identify and stop them. I enjoy approaching security from both the technical and human sides: testing carefully, documenting clearly, and learning with a team.
          </p>
          <div className="mt-8 grid gap-4 border-t border-[#2b3831] pt-6 sm:grid-cols-2">
            <div><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#c7f36a]">University lab work</p><p className="mt-2 text-sm leading-6 text-[#a0aea5]">Firewalls · IDS/IPS · Network segmentation · Controlled vulnerability assessments · Incident analysis</p></div>
            <div><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#c7f36a]">Languages</p><p className="mt-2 text-sm leading-6 text-[#a0aea5]">English <span className="text-[#68766d]">/ fluent</span><br />Nepali <span className="text-[#68766d]">/ native</span><br />Hindi <span className="text-[#68766d]">/ fluent</span></p></div>
          </div>
        </div>
      </div>
    </section>
  )
}

function ExperienceSection() {
  return (
    <section id="experience" className="mx-auto max-w-7xl px-5 py-16 sm:px-8 sm:py-20 lg:px-12 lg:py-24">
      <SectionHeading index="02" eyebrow="Experience" title="Learning by doing." description="A 10-week analyst program where cloud hardening, identity controls, and security visibility came together in practical work." />
      <article className="grid gap-8 border border-[#34423b] bg-[#101814] p-6 sm:p-8 lg:grid-cols-[.52fr_1fr] lg:gap-14 lg:p-10">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.14em] text-[#c7f36a]">2025 <span className="text-[#647168]">/</span> 10-week program</p>
          <h3 className="mt-4 text-2xl font-semibold tracking-[-0.035em] text-[#f1f4ee]">Cybersecurity Analyst Intern</h3>
          <p className="mt-2 text-sm text-[#a0aea5]">AusBiz Consulting</p>
          <p className="mt-1 text-sm text-[#77857c]">via Employability Advantage</p>
          <div className="mt-7 border-t border-[#2b3831] pt-5">
            <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-[#89978d]">Training</p>
            <p className="mt-2 text-sm font-medium text-[#e0e7e0]">Cybersecurity Analyst</p>
            <p className="mt-1 text-xs leading-5 text-[#89978d]">Statement of Completion · Employability Advantage · 2025</p>
          </div>
        </div>
        <ul className="flex flex-col gap-5">
          {experience.map((item, index) => (
            <li key={item} className="grid grid-cols-[2rem_1fr] gap-3 border-b border-[#29352f] pb-5 last:border-0 last:pb-0">
              <span className="font-mono text-xs text-[#c7f36a]">0{index + 1}</span>
              <p className="text-sm leading-6 text-[#b0bcb3]">{item}</p>
            </li>
          ))}
        </ul>
      </article>
    </section>
  )
}

function ProjectCard({ project }: { project: (typeof projects)[number] }) {
  const Icon = project.icon
  return (
    <article className="group flex min-h-full flex-col border border-[#34423b] bg-[#101814] p-6 transition-colors hover:border-[#71894f] sm:p-8">
      <div className="flex items-center justify-between">
        <span className="grid size-12 place-items-center border border-[#41503f] bg-[#18231b] text-[#c7f36a]"><Icon size={21} aria-hidden="true" /></span>
        <span className="font-mono text-xs text-[#77857c]">PROJECT / {project.number}</span>
      </div>
      <p className="mt-8 font-mono text-[10px] uppercase tracking-[0.17em] text-[#c7f36a]">{project.eyebrow}</p>
      <h3 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-[#f1f4ee] sm:text-3xl">{project.title}</h3>
      <p className="mt-4 flex-1 text-sm leading-7 text-[#a0aea5]">{project.description}</p>
      <div className="mt-6 flex flex-wrap gap-2" aria-label={`${project.title} topics`}>
        {project.tags.map((tag) => <span key={tag} className="border border-[#34423b] px-2.5 py-1.5 font-mono text-[10px] text-[#aeb9b0]">{tag}</span>)}
      </div>
      <a href={project.url} {...externalLinkProps} className="mt-8 inline-flex w-fit items-center gap-3 border-b border-[#607349] pb-2 text-sm font-semibold text-[#d6f69a] transition-colors hover:border-[#c7f36a] hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]">
        {project.action}<ArrowUpRight size={16} aria-hidden="true" className="transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
      </a>
    </article>
  )
}

function ProjectsSection() {
  return (
    <section id="projects" className="border-y border-[#26332c] bg-[#0d1411]">
      <div className="mx-auto max-w-7xl px-5 py-16 sm:px-8 sm:py-20 lg:px-12 lg:py-24">
        <SectionHeading index="03" eyebrow="Selected projects" title="Building to understand. Testing to defend." description="Two personal sites that bring together my interests in practical security and better ways to learn." />
        <div className="grid gap-4 lg:grid-cols-2">
          {projects.map((project) => <ProjectCard key={project.number} project={project} />)}
        </div>
        <p className="mt-5 max-w-3xl text-xs leading-5 text-[#77857c]">Security scenarios are built for controlled learning and defensive testing only. I do not test systems without permission.</p>
      </div>
    </section>
  )
}

function ToolkitSection() {
  return (
    <section id="toolkit" className="mx-auto max-w-7xl px-5 py-16 sm:px-8 sm:py-20 lg:px-12 lg:py-24">
      <SectionHeading index="04" eyebrow="Toolkit & education" title="A foundation I keep building on." description="Practical tools, core concepts, and a degree focused on understanding how secure systems are designed and defended." />
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {skillGroups.map(({ number, title, icon: Icon, items }) => (
          <article key={number} className="border border-[#34423b] bg-[#101814] p-5 sm:p-6">
            <div className="flex items-center justify-between"><span className="grid size-10 place-items-center border border-[#34423b] text-[#c7f36a]"><Icon size={17} aria-hidden="true" /></span><span className="font-mono text-xs text-[#77857c]">{number}</span></div>
            <h3 className="mt-5 text-base font-semibold text-[#e9eee8]">{title}</h3>
            <p className="mt-2 text-xs leading-6 text-[#98a69c]">{items}</p>
          </article>
        ))}
      </div>
      <div className="mt-5 grid gap-px border border-[#34423b] bg-[#34423b] md:grid-cols-2">
        <article className="bg-[#0a100e] p-6 sm:p-8">
          <div className="flex items-center gap-3 text-[#c7f36a]"><GraduationCap size={18} aria-hidden="true" /><p className="font-mono text-[10px] uppercase tracking-[0.15em]">Education</p></div>
          <h3 className="mt-5 text-lg font-semibold text-[#f1f4ee]">Bachelor of Cyber Security</h3>
          <p className="mt-2 text-sm text-[#a0aea5]">Victoria University · Sydney</p>
          <p className="mt-1 font-mono text-xs text-[#77857c]">August 2024 — June 2027 expected · Final year</p>
          <p className="mt-4 max-w-lg text-xs leading-6 text-[#89978d]">Focus areas include security architecture, threat analysis, advanced networking, system administration, and defensive security strategies.</p>
        </article>
        <article className="bg-[#0a100e] p-6 sm:p-8">
          <div className="flex items-center gap-3 text-[#c7f36a]"><Terminal size={17} aria-hidden="true" /><p className="font-mono text-[10px] uppercase tracking-[0.15em]">Practice beyond coursework</p></div>
          <h3 className="mt-5 text-lg font-semibold text-[#f1f4ee]">University security labs</h3>
          <p className="mt-2 text-sm leading-6 text-[#a0aea5]">Firewall configuration · IDS/IPS · Network segmentation · Controlled vulnerability assessment · Penetration-testing exercises · Malware and incident analysis</p>
        </article>
      </div>
    </section>
  )
}

function ContactSection() {
  return (
    <footer id="contact" className="border-t border-[#34423b] bg-[#0d1411]">
      <div className="mx-auto max-w-7xl px-5 py-14 sm:px-8 sm:py-16 lg:px-12 lg:py-20">
        <div className="grid gap-10 lg:grid-cols-[1fr_auto] lg:items-end">
          <div>
            <p className="section-label"><span>05</span> / Contact</p>
            <h2 className="mt-5 max-w-2xl text-3xl font-semibold leading-tight tracking-[-0.045em] text-[#f1f4ee] sm:text-5xl">Ready to learn, contribute, and grow with a security team.</h2>
            <p className="mt-4 text-sm text-[#a0aea5]">Open to cybersecurity and IT internship opportunities.</p>
          </div>
          <a href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com" {...externalLinkProps} className="inline-flex min-h-12 w-fit items-center gap-3 bg-[#c7f36a] px-5 text-sm font-semibold text-[#111811] transition-colors hover:bg-[#d8ff8c] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]">
            <Mail size={16} aria-hidden="true" /> Email Ashmin <ArrowRight size={15} aria-hidden="true" />
          </a>
        </div>
        <div className="mt-10 grid gap-3 border-t border-[#2b3831] pt-6 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <a className="inline-flex items-center gap-3 text-[#b0bcb3] transition-colors hover:text-[#c7f36a]" href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com" {...externalLinkProps}><Mail size={15} aria-hidden="true" /> ashminaryal111@gmail.com</a>
          <a className="inline-flex items-center gap-3 text-[#b0bcb3] transition-colors hover:text-[#c7f36a]" href="tel:+61424885009"><Phone size={15} aria-hidden="true" /> 0424 885 009</a>
          <a className="inline-flex items-center gap-3 text-[#b0bcb3] transition-colors hover:text-[#c7f36a]" href="https://www.linkedin.com/in/ashmin-aryal-b42bab2a9" {...externalLinkProps}><Linkedin size={15} aria-hidden="true" /> LinkedIn</a>
          <a className="inline-flex items-center gap-3 text-[#b0bcb3] transition-colors hover:text-[#c7f36a]" href="https://github.com/ashmin7" {...externalLinkProps}><Github size={15} aria-hidden="true" /> GitHub</a>
        </div>
        <div className="mt-10 flex flex-wrap items-center justify-between gap-3 border-t border-[#2b3831] pt-5 font-mono text-[10px] uppercase tracking-[0.12em] text-[#77857c]">
          <span>© 2026 Ashmin Aryal</span>
          <a href="#home" className="transition-colors hover:text-[#c7f36a]">Back to top ↑</a>
        </div>
      </div>
    </footer>
  )
}

export default function PortfolioPage() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#080d0b] text-[#f1f4ee]">
      <SiteHeader />
      <HeroSection />
      <AboutSection />
      <ExperienceSection />
      <ProjectsSection />
      <ToolkitSection />
      <ContactSection />
    </main>
  )
}
