export default function Footer() {
  return (
    <footer
      id="resources"
      className="border-t border-white/5 bg-black px-6 py-8 lg:px-10"
    >
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-5 sm:flex-row">

        {/* Left */}
        <div className="flex items-center gap-4">

          <span className="text-sm font-black italic text-white">
            BANTAI
          </span>

          <span className="text-xs text-zinc-600">
            © 2026 BANTAI Security Intelligence Inc. All rights reserved.
          </span>

        </div>

        {/* Right */}
        <div className="flex items-center gap-6 text-xs text-zinc-600">

          <a
            href="#privacy"
            className="transition-colors hover:text-white"
          >
            Privacy Policy
          </a>

          <a
            href="#terms"
            className="transition-colors hover:text-white"
          >
            Terms of Service
          </a>

          <a
            href="#contact"
            className="transition-colors hover:text-white"
          >
            Contact
          </a>

        </div>

      </div>
    </footer>
  );
}