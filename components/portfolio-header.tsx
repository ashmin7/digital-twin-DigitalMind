import Link from "next/link"
import { ArrowUpRight } from "lucide-react"

type PortfolioHeaderProps = {
  isHome: boolean
}

export function PortfolioHeader({ isHome }: PortfolioHeaderProps) {
  const sectionHref = (section: string) => (isHome ? `#${section}` : `/#${section}`)

  return (
    <header className="relative z-10 mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-5 py-5 sm:px-8 lg:px-12">
      <Link
        href={isHome ? "#home" : "/#home"}
        className="group inline-flex items-center gap-3 rounded-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]"
        aria-label="Ashmin Aryal, home"
      >
        <span className="grid size-10 place-items-center border border-[#34423b] bg-[#111a16] font-mono text-xs font-semibold text-[#c7f36a]">
          AA<span className="sr-only"> initials</span>
        </span>
        <span className="flex flex-col gap-0.5">
          <span className="text-sm font-semibold tracking-[0.08em] text-[#f1f4ee]">ASHMIN ARYAL</span>
          <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-[#829087]">Cybersecurity student</span>
        </span>
      </Link>

      <nav
        aria-label="Main navigation"
        className="order-3 flex w-full items-center gap-6 overflow-x-auto border-t border-[#25312b] pt-4 text-xs text-[#a0aea5] sm:order-none sm:w-auto sm:border-0 sm:pt-0 sm:text-sm"
      >
        <Link
          className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]"
          href="/about"
          aria-current={isHome ? undefined : "page"}
        >
          About
        </Link>
        <Link
          className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]"
          href={sectionHref("experience")}
        >
          Experience
        </Link>
        <Link
          className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]"
          href={sectionHref("projects")}
        >
          Projects
        </Link>
        <Link
          className="transition-colors hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#c7f36a]"
          href={sectionHref("toolkit")}
        >
          Toolkit
        </Link>
      </nav>

      <a
        href="https://mail.google.com/mail/?view=cm&fs=1&to=ashminaryal111%40gmail.com"
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-2 border border-[#405047] px-4 py-2.5 text-xs font-semibold text-[#f1f4ee] transition-colors hover:border-[#c7f36a] hover:text-[#c7f36a] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#c7f36a]"
      >
        Get in touch <ArrowUpRight size={14} aria-hidden="true" />
      </a>
    </header>
  )
}
