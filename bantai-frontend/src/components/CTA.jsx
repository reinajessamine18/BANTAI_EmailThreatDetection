import { Link } from "react-router-dom";

export default function CTA() {
  return (
    <section
      id="about"
      className="bg-black px-6 py-24 lg:px-10"
    >
      <div className="mx-auto max-w-7xl">

        <div className="relative overflow-hidden rounded-[30px] border-t-2 border-lime-400 bg-zinc-900/80 px-6 py-20 text-center shadow-[0_-10px_60px_rgba(190,255,0,0.08)] sm:px-10">

          {/* Background glow */}
          <div className="absolute left-1/2 top-0 h-64 w-96 -translate-x-1/2 rounded-full bg-lime-400/5 blur-[100px]" />

          <div className="relative">

            <h2 className="text-3xl font-black tracking-tight text-white sm:text-4xl lg:text-5xl">
              Experience transparent cyber defense.
            </h2>

            <p className="mx-auto mt-5 max-w-2xl text-sm leading-6 text-zinc-500 sm:text-base">
              Deploy an email security engine that doesn't just block threats,
              it explains them. Upload your first .eml payload today.
            </p>

            <div className="mt-9 flex flex-col items-center justify-center gap-4 sm:flex-row">

              <Link
                to="/login"
                className="rounded-full bg-lime-400 px-9 py-3.5 text-sm font-bold text-black transition-all hover:bg-lime-300 hover:shadow-[0_0_25px_rgba(190,255,0,0.3)]"
              >
                LOGIN
              </Link>

              <a
                href="#resources"
                className="rounded-full border border-lime-400 px-8 py-3.5 text-sm font-bold text-lime-400 transition-all hover:bg-lime-400 hover:text-black"
              >
                View User Manual
              </a>

            </div>

          </div>
        </div>

      </div>
    </section>
  );
}