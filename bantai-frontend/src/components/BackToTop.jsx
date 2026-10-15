import { useEffect, useState } from "react";

function BackToTop() {
  const [showButton, setShowButton] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setShowButton(window.scrollY > 500);
    };

    window.addEventListener("scroll", handleScroll);

    return () => {
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  if (!showButton) {
    return null;
  }

  return (
    <button
      type="button"
      onClick={scrollToTop}
      aria-label="Back to top"
      className="fixed bottom-7 right-7 z-50 flex h-12 w-12 items-center justify-center rounded-full border border-lime-400 bg-black text-xl font-bold text-lime-400 shadow-[0_0_20px_rgba(190,255,0,0.12)] transition-all duration-300 hover:-translate-y-1 hover:bg-lime-400 hover:text-black"
    >
      ↑
    </button>
  );
}

export default BackToTop;