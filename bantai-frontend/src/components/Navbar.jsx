import { Link } from "react-router-dom";

export default function Navbar() {
  return (
    <nav className="absolute left-0 right-0 top-0 z-50">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">

        {/* Logo */}
        <a
          href="#home"
          className="text-2xl font-black italic tracking-tight text-white">
          BANTAI<span className="text-lime-400">.</span>
        </a>

        {/* Navigation */}
        <div className="flex items-center gap-10 text-sm text-zinc-400">
          <a
            href="#platform"
            className="transition-colors hover:text-white"
          >
            Platform
          </a>

          <a
            href="#solutions"
            className="transition-colors hover:text-white"
          >
            Solutions
          </a>

          <a
            href="#resources"
            className="transition-colors hover:text-white"
          >
            Resources
          </a>
        </div>

      </div>
    </nav>
  );
}