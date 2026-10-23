import { Link } from "react-router-dom";

import backgroundImage from "../assets/bantai-background.webp";
import heroImage from "../assets/BANTAI-3D.webp";

export default function Hero() {
  return (
    <section
      id="home"
      className="relative min-h-[700px] overflow-hidden bg-black"
    >
      <div
        className="absolute inset-0 bg-cover bg-center bg-no-repeat"
        style={{
          backgroundImage: `url(${backgroundImage})`,
        }}
      />

      <div className="absolute inset-0 bg-black/30" />

      <div className="absolute right-[15%] top-[25%] h-[500px] w-[500px] rounded-full bg-lime-400/10 blur-[120px]" />

      <div className="relative mx-auto grid min-h-[700px] max-w-7xl items-center gap-10 px-6 pb-20 pt-32 lg:grid-cols-2 lg:px-10">

        <div className="relative z-10 max-w-2xl">

          <h1 className="text-5xl font-black leading-[0.95] tracking-tight text-white sm:text-6xl lg:text-7xl">
            Stop Phishing
            <br />
            Attacks Before
            <br />
            They Strike.
          </h1>

          <p className="mt-7 max-w-lg text-base leading-7 text-zinc-400 sm:text-lg">
            The XGBoost-powered threat analysis engine.
            Empower users with rapid phishing detection 
            and SHAP-driven explainability.
          </p>

          <div className="mt-8">

            <Link
              to="/login"
              className="inline-flex items-center gap-3 rounded-full bg-lime-400 px-7 py-4 text-sm font-bold text-black transition-all hover:bg-lime-300 hover:shadow-[0_0_30px_rgba(190,255,0,0.35)]"
            >
              Scan an Email
            </Link>

          </div>

        </div>

        <div className="relative h-[520px]">

          <img
            src={heroImage}
            alt="BANTAI email threat analysis"
            className="absolute left-1/2 top-1/2 w-[700px] max-w-none -translate-x-1/2 -translate-y-1/2 object-contain"
          />

        </div>

      </div>
    </section>
  );
}