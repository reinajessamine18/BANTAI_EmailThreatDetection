import Navbar from "./components/Navbar";
import Hero from "./components/Hero";
import TechStack from "./components/TechStack";
import Advantage from "./components/Advantage";
import CTA from "./components/CTA";
import Footer from "./components/Footer";

function App() {
  return (
    <div className="min-h-screen bg-black text-white">
      <Navbar />
      <Hero />
      <TechStack />
      <Advantage />
      <CTA />
      <Footer />
    </div>
  );
}

export default App;