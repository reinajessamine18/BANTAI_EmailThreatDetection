import rapidThreatIcon from "../assets/rapid-threat.png";
import transparentAIIcon from "../assets/transparent-ai.png";
import userEducationIcon from "../assets/user-education.png";

const advantages = [
  {
    icon: rapidThreatIcon,
    title: "Rapid Threat Inference",
    description:
      "Utilizing an Extreme Gradient Boosting (XGBoost) architecture, BANTAI evaluates high-dimensional email metadata and URL properties in under 100 milliseconds.",
    link: "View architecture",
  },
  {
    icon: transparentAIIcon,
    title: "Transparent AI Decisions",
    description:
      'Eliminate the "black box." Our integrated SHAP Explainability Framework breaks down every prediction, showing you exactly which features triggered a phishing alert.',
    link: "Explore XAI",
  },
  {
    icon: userEducationIcon,
    title: "User-Centric Education",
    description:
      "Transform passive users into active defenders. BANTAI translates complex mathematical Shapley values into plain-language insights to build security awareness.",
    link: "Learn more",
  },
];

export default function Advantage() {
  return (
    <section
      id="solutions"
      className="bg-black px-6 py-24 lg:px-10"
    >
      <div className="mx-auto max-w-7xl">

        {/* Heading */}
        <div className="mb-14">
          <p className="mb-4 text-xs font-bold uppercase tracking-[0.25em] text-lime-400">
            The BANTAI Advantage
          </p>

          <h2 className="max-w-4xl text-4xl font-black leading-tight tracking-tight text-white sm:text-5xl lg:text-6xl">
            Algorithmic precision meets
            <br />
            human-centric explainability.
          </h2>
        </div>

        {/* Cards */}
        <div className="grid gap-4 lg:grid-cols-3">
          {advantages.map((advantage) => (
            <article
              key={advantage.title}
              className="group min-h-[300px] rounded-2xl border border-lime-400/20 bg-zinc-900/60 p-6 transition-all duration-300 hover:-translate-y-1 hover:border-lime-400/50 hover:bg-zinc-900"
            >

              {/* Icon */}
             <div className="mb-12 flex h-9 w-9 items-center justify-center rounded-lg bg-lime-400/10">
            <img
                src={advantage.icon}
                alt=""
                className="h-5 w-5 object-contain"
            />
            </div>

              {/* Title */}
              <h3 className="mb-4 text-xl font-bold text-white">
                {advantage.title}
              </h3>

              {/* Description */}
              <p className="mb-8 text-sm leading-6 text-zinc-500">
                {advantage.description}
              </p>

              {/* Link */}
              <a
                href="#resources"
                className="text-xs font-bold text-lime-400 transition-colors hover:text-lime-300"
              >
                {advantage.link} →
              </a>

            </article>
          ))}
        </div>

      </div>
    </section>
  );
}