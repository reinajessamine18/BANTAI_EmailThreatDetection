export default function Navbar() {
  return (
    <nav className="absolute top-0 left-0 right-0 z-50">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10">
        
        {/* Logo */}
        <a
          href="#home"
          className="text-2xl font-black italic tracking-tight text-white">
          BANTAI
        </a>

        {/* Navigation */}
        <div className="hidden items-center gap-10 text-sm text-zinc-400 md:flex">
          <a
            href="#platform"
            className="transition-colors hover:text-white">
            Platform
          </a>

          <a
            href="#solutions"
            className="transition-colors hover:text-white">
            Solutions
          </a>

          <a
            href="#resources"
            className="transition-colors hover:text-white">
            Resources
          </a>
        </div>

      </div>
    </nav>
  );
}