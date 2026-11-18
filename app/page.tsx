import Link from "next/link"
import {
  ArrowDown,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Cloud,
  Github,
  Linkedin,
  Mail,
  Network,
  Shield,
  ShieldCheck,
  Terminal,
} from "lucide-react"

const skills = [
  { title: "Cloud security", items: "AWS IAM policies · Cognito MFA · CloudWatch monitoring · Secrets Manager · API Gateway · Azure fundamentals" },
  { title: "Identity & access", items: "Least-privilege access · User permissions · Multi-factor authentication · Certificate-based API security" },
  { title: "Security operations", items: "Security event monitoring · Alerting and dashboards · Incident detection · Threat research" },
  { title: "Network defence", items: "TCP/IP · DNS · Firewall rules · IDS/IPS · Network segmentation · LAN/WAN" },
  { title: "Systems & assessment", items: "Windows Server · Active Directory · Ubuntu Linux · Vulnerability assessment · Controlled penetration-testing labs" },
  { title: "Development & tooling", items: "Next.js · TypeScript · Supabase · Vercel · GitHub · Virtual machines" },
]

const securityFocus = [
  { title: "Protect identity & data", detail: "Use scoped permissions, MFA, secrets management, and safer API connections to reduce unnecessary exposure." },
  { title: "See what is happening", detail: "Build monitoring dashboards and alerts that bring security-relevant events into view for investigation." },
  { title: "Understand the attack surface", detail: "Practice vulnerability assessment and common web-attack scenarios in controlled learning environments." },
  { title: "Strengthen the network", detail: "Explore firewalls, IDS/IPS, segmentation, and core networking concepts as layers of defensive control." },
]

const projects = [
  {
    name: "Live Hacking Lab 1",
    type: "Cybersecurity lab · featured",
    description: "A live, controlled environment for exploring web security scenarios and defensive measures, including authentication, access control, and activity logging.",
    url: "https://digital-twin-digitalmind222.vercel.app",
    linkLabel: "Open live hacking lab",
    tags: ["Web security", "Authentication", "Logging", "Next.js"],
  },
  {
    name: "Digital Twin DigitalMind 111",
    type: "Cybersecurity portfolio deployment",
    description: "A deployed Digital Twin project from my security portfolio work. Visit the live site to explore the project directly.",
    url: "https://digital-twin-digitalmind111-ashmin7s-projects.vercel.app",
    linkLabel: "Open Digital Twin 111",
    tags: ["Digital Twin", "Cybersecurity", "Live deployment"],
  },
  {
    name: "AI Study Assistant",
    type: "AI learning project",
    description: "An AI-focused study project that reflects my interest in applying modern web tools to make learning and technical concepts easier to explore.",
    url: "https://notes.ashminaryal.info",
    linkLabel: "Open AI Study Assistant",
    tags: ["AI", "Learning", "Web development"],
  },
  {
    name: "My Digital Portfolio",
    type: "Personal portfolio project",
    description: "A personal site for presenting my learning, technical interests, and project work in one place.",
    url: "https://ashminaryal.info",
    linkLabel: "Open digital portfolio",
    tags: ["Portfolio", "Web development", "Vercel"],
  },
]

const experience = [
  "Hardened AWS and Azure environments through IAM permissions, secrets management, and database firewall rules.",
  "Implemented MFA with AWS Cognito and protected API connections with API Gateway and mutual TLS certificates.",
  "Built CloudWatch dashboards and alerts to surface security events for faster investigation.",
  "Collaborated in an Agile team and used AI-assisted tools to support vulnerability testing and threat research.",
]

export default function Home() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#f7f8f5] text-[#15251f]">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-5 py-5 sm:px-8">
        <Link href="#home" className="flex items-center gap-3" aria-label="Ashmin Aryal, home">
          <span className="grid size-10 place-items-center rounded-full bg-[#173b32] text-sm font-bold text-[#d5f46a]">AA</span>
          <span className="text-sm font-semibold tracking-tight">ASHMIN ARYAL</span>
        </Link>
        <nav aria-label="Main navigation" className="hidden items-center gap-8 text-sm text-[#53645d] md:flex">
          <Link className="transition hover:text-[#15251f]" href="#about">About</Link>
          <Link className="transition hover:text-[#15251f]" href="#experience">Experience</Link>
          <Link className="transition hover:text-[#15251f]" href="#projects">Projects</Link>
          <Link className="transition hover:text-[#15251f]" href="#skills">Skills</Link>
        </nav>
        <a href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com" target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-full border border-[#cbd4cc] px-4 py-2 text-sm font-medium transition hover:border-[#173b32] hover:bg-white">
          Get in touch <ArrowUpRight aria-hidden="true" size={15} />
        </a>
      </header>

      <section id="home" className="relative mx-auto grid max-w-6xl gap-12 px-5 pb-20 pt-14 sm:px-8 sm:pt-20 lg:grid-cols-[1.2fr_.8fr] lg:items-center lg:pb-28 lg:pt-24">
        <div className="absolute -right-36 -top-36 -z-0 size-[28rem] rounded-full border border-[#e1e7df] sm:-right-20" aria-hidden="true" />
        <div className="relative z-10">
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-[#d8e1d5] bg-white/70 px-3 py-1.5 text-xs font-medium text-[#48665b]">
            <span className="size-2 rounded-full bg-[#a4cb42]" /> CYBERSECURITY · SYDNEY, AUSTRALIA
          </div>
          <h1 className="max-w-3xl text-5xl font-semibold leading-[1.04] tracking-[-0.055em] sm:text-6xl lg:text-7xl">
            Building safer<br className="hidden sm:block" /> systems, <span className="font-serif italic text-[#6e8f32]">one layer</span><br className="hidden sm:block" /> at a time.
          </h1>
          <p className="mt-7 max-w-xl text-base leading-7 text-[#53645d] sm:text-lg sm:leading-8">
            I&apos;m Ashmin, a final-year Cyber Security student with hands-on experience in cloud security, identity protection, and security monitoring. I&apos;m looking for an opportunity to learn, contribute, and grow with a security team.
          </p>
          <div className="mt-9 flex flex-wrap items-center gap-3">
            <a href="https://www.linkedin.com/in/ashmin-aryal-b42bab2a9" target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-full bg-[#173b32] px-5 py-3 text-sm font-medium text-white transition hover:bg-[#245446]">
              Let&apos;s connect <ArrowUpRight aria-hidden="true" size={16} />
            </a>
            <Link href="#projects" className="inline-flex items-center gap-2 rounded-full border border-[#cbd4cc] px-5 py-3 text-sm font-medium transition hover:bg-white">
              Explore my work <ArrowDown aria-hidden="true" size={15} />
            </Link>
          </div>
          <div className="mt-10 flex flex-wrap gap-x-6 gap-y-3 text-sm text-[#53645d]">
            <a className="inline-flex items-center gap-2 hover:text-[#15251f]" href="https://www.linkedin.com/in/ashmin-aryal-b42bab2a9" target="_blank" rel="noreferrer"><Linkedin size={16} aria-hidden="true" /> linkedin.com/in/ashmin-aryal-b42bab2a9</a>
            <a className="inline-flex items-center gap-2 hover:text-[#15251f]" href="https://github.com/ashmin7" target="_blank" rel="noreferrer"><Github size={16} aria-hidden="true" /> GitHub</a>
            <a className="inline-flex items-center gap-2 hover:text-[#15251f]" href="https://ashminaryal.info" target="_blank" rel="noreferrer"><ArrowUpRight size={16} aria-hidden="true" /> Portfolio</a>
          </div>
        </div>

        <aside className="relative z-10 rounded-[1.75rem] bg-[#173b32] p-6 text-white shadow-[0_28px_80px_-42px_rgba(23,59,50,.55)] sm:p-8" aria-label="Professional profile summary">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium uppercase tracking-[.2em] text-[#c3d7ca]">Currently focused on</p>
              <h2 className="mt-3 text-2xl font-medium tracking-tight">Cloud & defensive security</h2>
            </div>
            <span className="grid size-12 place-items-center rounded-2xl bg-white/10 text-[#d5f46a]"><ShieldCheck size={23} aria-hidden="true" /></span>
          </div>
          <div className="mt-8 rounded-2xl border border-white/10 bg-[#102f28] p-5 font-mono text-xs leading-7 text-[#c3d7ca] sm:text-sm">
            <p><span className="text-[#d5f46a]">$</span> whoami</p>
            <p className="text-white">Cybersecurity student · builder</p>
            <p><span className="text-[#d5f46a]">$</span> location</p>
            <p className="text-white">Ashfield, NSW, Australia</p>
            <p><span className="text-[#d5f46a]">$</span> status</p>
            <p className="text-white">Open to cybersecurity / IT internships</p>
          </div>
          <div className="mt-6 grid grid-cols-2 gap-3">
            <div className="rounded-2xl bg-white/5 p-4"><Cloud className="mb-3 text-[#d5f46a]" size={19} aria-hidden="true" /><p className="text-sm font-medium">Cloud hardening</p><p className="mt-1 text-xs text-[#c3d7ca]">AWS · Azure</p></div>
            <div className="rounded-2xl bg-white/5 p-4"><Network className="mb-3 text-[#d5f46a]" size={19} aria-hidden="true" /><p className="text-sm font-medium">Threat visibility</p><p className="mt-1 text-xs text-[#c3d7ca]">Alerts · dashboards</p></div>
          </div>
        </aside>
      </section>

      <section id="about" className="border-y border-[#e2e7df] bg-white/60">
        <div className="mx-auto grid max-w-6xl gap-8 px-5 py-14 sm:px-8 sm:py-16 md:grid-cols-[.55fr_1fr] md:gap-16">
          <div><p className="text-xs font-semibold uppercase tracking-[.2em] text-[#718e3d]">01 / About</p><h2 className="mt-4 text-3xl font-semibold tracking-tight sm:text-4xl">Curious by nature.<br />Security-minded by design.</h2></div>
          <div className="max-w-2xl text-base leading-7 text-[#53645d]">
            <p>I&apos;m completing a Bachelor of Cyber Security at Victoria University in Sydney. Through a 10-week analyst internship and university labs, I&apos;ve worked across cloud controls, identity and access, network defence, and vulnerability assessment.</p>
            <p className="mt-4">Outside coursework, I built Digital Twin III—a live security lab that helps me explore common web threats and the defensive controls that detect or block them. I bring a practical mindset, clear communication, and a genuine eagerness to keep learning.</p>
            <div className="mt-6 flex flex-wrap gap-2"><span className="rounded-full bg-[#edf2e8] px-3 py-1.5 text-xs font-medium text-[#405748]">English · Fluent</span><span className="rounded-full bg-[#edf2e8] px-3 py-1.5 text-xs font-medium text-[#405748]">Nepali · Native</span><span className="rounded-full bg-[#edf2e8] px-3 py-1.5 text-xs font-medium text-[#405748]">Hindi · Fluent</span></div>
          </div>
        </div>
      </section>

      <section id="experience" className="mx-auto max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
        <div className="mb-10 flex flex-wrap items-end justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-[.2em] text-[#718e3d]">02 / Experience</p><h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Learning by doing.</h2></div><p className="text-sm text-[#718078]">A foundation built through hands-on work</p></div>
        <article className="grid gap-8 rounded-[1.75rem] border border-[#e1e7df] bg-white p-6 sm:p-8 md:grid-cols-[.38fr_1fr] md:p-10">
          <div><p className="text-xs font-semibold uppercase tracking-[.16em] text-[#718e3d]">2025 · 10-week program</p><h3 className="mt-3 text-xl font-semibold">Cybersecurity Analyst Intern</h3><p className="mt-2 text-sm text-[#53645d]">AusBiz Consulting<br />via Employability Advantage</p><span className="mt-5 inline-flex rounded-full bg-[#edf2e8] px-3 py-1.5 text-xs font-medium text-[#405748]">Intensive internship</span></div>
          <ul className="flex flex-col gap-4">
            {experience.map((item) => <li key={item} className="flex gap-3 text-sm leading-6 text-[#53645d]"><span className="mt-2 size-1.5 shrink-0 rounded-full bg-[#8cac4d]" />{item}</li>)}
          </ul>
        </article>
      </section>

      <section aria-labelledby="security-focus-heading" className="border-y border-[#dce5dc] bg-[#eef2eb]">
        <div className="mx-auto max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
          <div className="mb-10 max-w-2xl">
            <p className="text-xs font-semibold uppercase tracking-[.2em] text-[#718e3d]">03 / Security focus</p>
            <h2 id="security-focus-heading" className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">A practical, defence-first mindset.</h2>
            <p className="mt-4 text-base leading-7 text-[#53645d]">My learning connects identity, cloud configuration, network controls, and visibility—so I can understand how security measures work together, not in isolation.</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {securityFocus.map((item, index) => <article key={item.title} className="rounded-2xl border border-[#d8e1d6] bg-white p-5"><div className="mb-5 flex items-center justify-between"><span className="grid size-10 place-items-center rounded-xl bg-[#e8efe3] text-[#43644b]"><Shield size={19} aria-hidden="true" /></span><span className="font-mono text-xs text-[#8a9a8e]">0{index + 1}</span></div><h3 className="font-semibold tracking-tight">{item.title}</h3><p className="mt-2 text-sm leading-6 text-[#64736b]">{item.detail}</p></article>)}
          </div>
        </div>
      </section>

      <section id="projects" className="bg-[#173b32] text-white">
        <div className="mx-auto max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
          <div className="mb-10 flex flex-wrap items-end justify-between gap-4"><div><p className="text-xs font-semibold uppercase tracking-[.2em] text-[#d5f46a]">04 / Projects</p><h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Work I&apos;ve put into the world.</h2></div><p className="max-w-sm text-sm leading-6 text-[#c3d7ca]">Explore my cybersecurity, AI learning, and portfolio projects.</p></div>
          <div className="grid gap-4 md:grid-cols-2">
            {projects.map((project, index) => <article key={project.name} className="flex flex-col rounded-[1.5rem] border border-white/15 bg-white/[.06] p-6 transition-colors hover:bg-white/[.09] sm:p-7">
              <div className="flex items-center justify-between"><span className="grid size-11 place-items-center rounded-xl bg-[#d5f46a] text-[#173b32]"><Terminal size={20} aria-hidden="true" /></span><span className="font-mono text-xs text-[#c3d7ca]">PROJECT 0{index + 1}</span></div>
              <p className="mt-6 text-xs font-semibold uppercase tracking-[.15em] text-[#d5f46a]">{project.type}</p>
              <h3 className="mt-2 text-2xl font-medium tracking-tight">{project.name}</h3>
              <p className="mt-3 flex-1 text-sm leading-6 text-[#c3d7ca]">{project.description}</p>
              <div className="mt-5 flex flex-wrap gap-2">{project.tags.map((tag) => <span key={tag} className="rounded-full border border-white/15 px-3 py-1 text-xs text-[#dce8e0]">{tag}</span>)}</div>
              <a href={project.url} target="_blank" rel="noreferrer" className="mt-6 inline-flex w-fit items-center gap-2 text-sm font-medium text-[#d5f46a] hover:text-white">{project.linkLabel} <ArrowUpRight size={15} aria-hidden="true" /></a>
            </article>)}
          </div>
          <div className="mt-5 rounded-2xl border border-white/10 bg-[#102f28]/60 p-5 sm:flex sm:items-center sm:justify-between sm:gap-8"><div><p className="text-xs font-semibold uppercase tracking-[.15em] text-[#d5f46a]">Academic project work</p><p className="mt-2 text-sm leading-6 text-[#c3d7ca]">University security labs: firewall configuration, IDS/IPS testing, network segmentation, controlled vulnerability assessments, penetration-testing exercises, and malware / incident analysis.</p></div><span className="mt-4 inline-flex shrink-0 rounded-full border border-white/15 px-3 py-1 text-xs text-[#dce8e0] sm:mt-0">Victoria University</span></div>
        </div>
      </section>

      <section id="skills" className="mx-auto max-w-6xl px-5 py-16 sm:px-8 sm:py-20">
        <div className="mb-10"><p className="text-xs font-semibold uppercase tracking-[.2em] text-[#718e3d]">05 / Toolkit</p><h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">Skills I&apos;m building on.</h2></div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {skills.map((skill, index) => <article key={skill.title} className="rounded-2xl border border-[#e1e7df] bg-white p-5"><div className="flex items-center justify-between"><h3 className="font-semibold">{skill.title}</h3><span className="text-xs font-mono text-[#8a9a8e]">0{index + 1}</span></div><p className="mt-3 text-sm leading-6 text-[#64736b]">{skill.items}</p></article>)}
        </div>
        <div className="mt-10 grid gap-5 border-t border-[#e1e7df] pt-8 sm:grid-cols-2">
          <div><p className="text-xs font-semibold uppercase tracking-[.16em] text-[#718e3d]">Education</p><h3 className="mt-3 font-semibold">Bachelor of Cyber Security</h3><p className="mt-1 text-sm text-[#64736b]">Victoria University, Sydney · Aug 2024 – Jun 2027 (expected)</p><p className="mt-2 text-sm leading-6 text-[#64736b]">Final year · Security architecture, threat analysis, networking, and system administration</p></div>
          <div><p className="text-xs font-semibold uppercase tracking-[.16em] text-[#718e3d]">Training</p><h3 className="mt-3 font-semibold">Cybersecurity Analyst</h3><p className="mt-1 text-sm text-[#64736b]">Statement of Completion · Employability Advantage · 2025</p><p className="mt-2 text-sm leading-6 text-[#64736b]">10-week intensive program in cloud hardening, identity security, API protection, and threat intelligence.</p></div>
        </div>
      </section>

      <footer className="border-t border-[#e1e7df] bg-white">
        <div className="mx-auto flex max-w-6xl flex-col gap-7 px-5 py-10 sm:px-8 md:flex-row md:items-center md:justify-between">
          <div><p className="text-xs font-semibold uppercase tracking-[.2em] text-[#718e3d]">Have an opportunity?</p><h2 className="mt-2 text-2xl font-semibold tracking-tight">Let&apos;s make security stronger.</h2></div>
          <div className="flex flex-wrap gap-3"><a href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com" target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-full bg-[#173b32] px-5 py-3 text-sm font-medium text-white hover:bg-[#245446]"><Mail size={16} aria-hidden="true" /> Email me <ArrowRight size={15} aria-hidden="true" /></a><a href="https://www.linkedin.com/in/ashmin-aryal-b42bab2a9" target="_blank" rel="noreferrer" aria-label="Connect on LinkedIn" className="grid size-11 place-items-center rounded-full border border-[#cbd4cc] hover:bg-[#f7f8f5]"><Linkedin size={17} aria-hidden="true" /></a><a href="https://github.com/ashmin7" target="_blank" rel="noreferrer" aria-label="View GitHub profile" className="grid size-11 place-items-center rounded-full border border-[#cbd4cc] hover:bg-[#f7f8f5]"><Github size={17} aria-hidden="true" /></a></div>
        </div>
        <div className="mx-auto flex max-w-6xl justify-between border-t border-[#e1e7df] px-5 pt-4 pb-20 text-xs text-[#718078] sm:px-8 sm:pb-6"><span>© 2026 Ashmin Aryal</span><a href="#home" className="inline-flex items-center gap-1 hover:text-[#15251f]">Back to top <ArrowDownRight size={13} aria-hidden="true" className="-rotate-90" /></a></div>
      </footer>
    </main>
  )
}
