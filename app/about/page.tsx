import type { Metadata } from "next"
import Link from "next/link"
import {
  ArrowLeft,
  ArrowUpRight,
  Cloud,
  GraduationCap,
  MapPin,
  Network,
  ShieldCheck,
  Terminal,
} from "lucide-react"
import { PortfolioHeader } from "@/components/portfolio-header"

export const metadata: Metadata = {
  title: "About Ashmin Aryal",
  description:
    "Get to know Ashmin Aryal, a Cyber Security student at Victoria University focused on cloud security, identity, and defensive monitoring.",
}

const focusAreas = [
  { label: "Cloud security", detail: "AWS · Azure", icon: Cloud },
  { label: "Identity & access", detail: "IAM · MFA · mTLS", icon: Network },
  { label: "Security visibility", detail: "Alerts · CloudWatch", icon: Terminal },
]

export default function AboutPage() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#080d0b] text-[#f1f4ee]">
      <PortfolioHeader isHome={false} />

      <section
        aria-labelledby="about-title"
        className="relative mx-auto max-w-7xl px-5 pb-16 pt-10 sm:px-8 sm:pb-20 lg:px-12 lg:pb-24 lg:pt-14"
      >
        <div className="portfolio-grid pointer-events-none absolute inset-0 -z-10" aria-hidden="true" />
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-sm text-[#a0aea5] transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]"
        >
          <ArrowLeft size={15} aria-hidden="true" /> Back to portfolio
        </Link>

        <div className="mt-12 grid gap-10 lg:grid-cols-[1.1fr_.9fr] lg:items-center lg:gap-16">
          <div>
            <p className="section-label"><span>01</span> / About me</p>
            <h1
              id="about-title"
              className="mt-5 max-w-3xl text-[clamp(3rem,7vw,5.75rem)] font-semibold leading-[0.98] tracking-[-0.065em] text-[#f1f4ee]"
            >
              I&apos;m <span className="text-[#c7f36a]">Ashmin Aryal.</span>
            </h1>
            <p className="mt-7 max-w-2xl text-base leading-8 text-[#d0d8d1] sm:text-lg">
              I&apos;m a final-year Cyber Security student at Victoria University in Sydney. I&apos;m building practical experience across cloud security, identity, and defensive monitoring—and looking for a cybersecurity or IT internship where I can keep learning and contribute.
            </p>
            <p className="mt-5 max-w-2xl text-sm leading-7 text-[#a0aea5] sm:text-base">
              During a 10-week analyst internship and university security labs, I&apos;ve worked with cloud controls, identity and access, network defense, and vulnerability assessment. I enjoy testing carefully, documenting clearly, and learning with a team.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3 font-mono text-xs uppercase tracking-[0.14em] text-[#9aa89e]">
              <span className="inline-flex items-center gap-2"><MapPin size={14} aria-hidden="true" /> Sydney, Australia</span>
              <span className="text-[#536158]" aria-hidden="true">/</span>
              <span>Victoria University</span>
            </div>
          </div>

          <aside
            aria-label="Areas of cybersecurity focus"
            className="relative border border-[#34423b] bg-[#101814]/90 p-5 shadow-[0_30px_100px_-55px_rgba(0,0,0,.9)] sm:p-7"
          >
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[#c7f36a] to-transparent" aria-hidden="true" />
            <div className="flex items-center justify-between border-b border-[#27332d] pb-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#a0aea5]">What I&apos;m focused on</p>
              <ShieldCheck size={16} className="text-[#c7f36a]" aria-hidden="true" />
            </div>
            <div className="mt-3">
              {focusAreas.map(({ label, detail, icon: Icon }, index) => (
                <div key={label} className="grid grid-cols-[2rem_2.25rem_1fr] items-center gap-3 border-b border-[#27332d] py-5 last:border-0">
                  <span className="font-mono text-[10px] text-[#75847a]">0{index + 1}</span>
                  <span className="grid size-9 place-items-center border border-[#34423b] bg-[#17211b] text-[#c7f36a]">
                    <Icon size={16} aria-hidden="true" />
                  </span>
                  <div>
                    <p className="text-sm font-medium text-[#f1f4ee]">{label}</p>
                    <p className="mt-1 font-mono text-[10px] text-[#94a197]">{detail}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-2 flex items-center justify-between border-t border-[#27332d] pt-4 font-mono text-[10px] uppercase tracking-[0.12em] text-[#829087]">
              <span>Study → build → defend</span>
              <span>2027 <span className="sr-only">degree expected</span></span>
            </div>
          </aside>
        </div>

        <div className="mt-14 grid gap-4 border-t border-[#34423b] pt-8 md:grid-cols-2">
          <article className="border border-[#34423b] bg-[#101814] p-6 sm:p-8">
            <div className="flex items-center gap-3 text-[#c7f36a]">
              <GraduationCap size={18} aria-hidden="true" />
              <p className="font-mono text-[10px] uppercase tracking-[0.15em]">Education & practice</p>
            </div>
            <h2 className="mt-5 text-xl font-semibold text-[#f1f4ee]">Learning by doing.</h2>
            <p className="mt-3 text-sm leading-7 text-[#a0aea5]">
              I&apos;m completing a Bachelor of Cyber Security at Victoria University. My coursework and projects cover firewalls, IDS/IPS, network segmentation, controlled vulnerability assessments, and incident analysis.
            </p>
          </article>
          <article className="border border-[#34423b] bg-[#101814] p-6 sm:p-8">
            <div className="flex items-center gap-3 text-[#c7f36a]">
              <ShieldCheck size={18} aria-hidden="true" />
              <p className="font-mono text-[10px] uppercase tracking-[0.15em]">How I work</p>
            </div>
            <h2 className="mt-5 text-xl font-semibold text-[#f1f4ee]">Curious, careful, collaborative.</h2>
            <p className="mt-3 text-sm leading-7 text-[#a0aea5]">
              I approach security from both the technical and human sides: understand the system, test with permission, communicate findings clearly, and work with others to improve defenses.
            </p>
          </article>
        </div>

        <div className="mt-10 flex flex-wrap items-center justify-between gap-4 border-t border-[#2b3831] pt-6">
          <p className="text-sm text-[#a0aea5]">Open to cybersecurity and IT internship opportunities.</p>
          <a
            href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex min-h-11 items-center gap-2 bg-[#c7f36a] px-5 text-sm font-semibold text-[#111811] transition-colors hover:bg-[#d8ff8c] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]"
          >
            Get in touch <ArrowUpRight size={15} aria-hidden="true" />
          </a>
        </div>
      </section>
    </main>
  )
}
