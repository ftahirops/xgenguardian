import Nav from "@/components/Nav";
import Hero from "@/components/Hero";
import Differentiators from "@/components/Differentiators";
import HowItWorks from "@/components/HowItWorks";
import Comparison from "@/components/Comparison";
import Demo from "@/components/Demo";
import Pricing from "@/components/Pricing";
import FAQ from "@/components/FAQ";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <>
      <Nav />
      <Hero />
      <Differentiators />
      <HowItWorks />
      <Comparison />
      <Demo />
      <Pricing />
      <FAQ />
      <Footer />
    </>
  );
}
