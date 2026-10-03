import reactIcon from "../assets/react-icon.png";
import fastapiIcon from "../assets/fastapi-icon.png";
import xgboostIcon from "../assets/xgboost-icon.png";
import shapIcon from "../assets/shap-icon.png";
import sqliteIcon from "../assets/sqlite-icon.png";

const technologies = [
  {
    name: "React",
    icon: reactIcon,
  },
  {
    name: "FastAPI",
    icon: fastapiIcon,
  },
  {
    name: "XGBoost",
    icon: xgboostIcon,
  },
  {
    name: "SHAP",
    icon: shapIcon,
  },
  {
    name: "SQLite",
    icon: sqliteIcon,
  },
];

export default function TechStack() {
  return (
    <section className="border-b border-white/5 bg-black px-6 pb-24 pt-4">
      <div className="mx-auto max-w-5xl">

        <p className="mb-8 text-center text-[9px] font-semibold uppercase tracking-[0.35em] text-zinc-600">
          Evaluated and tested using ISO/IEC 25010 software quality standards
        </p>

        <div className="flex flex-wrap items-center justify-center gap-10 text-zinc-600 sm:gap-16">
          {technologies.map((technology) => (
            <div
              key={technology.name}
              className="flex items-center gap-2 text-sm font-semibold transition-colors hover:text-zinc-300"
            >
              <img
                src={technology.icon}
                alt={`${technology.name} logo`}
                className="h-6 w-6 object-contain"
              />

              <span>
                {technology.name}
              </span>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}