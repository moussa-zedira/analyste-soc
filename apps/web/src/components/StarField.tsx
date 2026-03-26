"use client";

import { useEffect, useRef } from "react";

interface Star {
  x: number;
  y: number;
  size: number;
  opacity: number;
  speed: number;
  delay: number;
}

const LAYER_CONFIG = [
  { count: 60, sizeRange: [0.3, 1.0], opacityRange: [0.05, 0.3], parallaxFactor: 0.01 },
  { count: 40, sizeRange: [0.5, 1.5], opacityRange: [0.1, 0.5], parallaxFactor: 0.025 },
  { count: 20, sizeRange: [1.0, 2.5], opacityRange: [0.2, 0.7], parallaxFactor: 0.05 },
];

function generateLayerStars(
  count: number,
  sizeRange: number[],
  opacityRange: number[],
): Star[] {
  return Array.from({ length: count }, () => ({
    x: Math.random() * 100,
    y: Math.random() * 100,
    size: Math.random() * (sizeRange[1] - sizeRange[0]) + sizeRange[0],
    opacity: Math.random() * (opacityRange[1] - opacityRange[0]) + opacityRange[0],
    speed: Math.random() * 3 + 2,
    delay: Math.random() * 5,
  }));
}

export function StarField() {
  const layersRef = useRef(
    LAYER_CONFIG.map((cfg) =>
      generateLayerStars(cfg.count, cfg.sizeRange, cfg.opacityRange),
    ),
  );
  const layerElsRef = useRef<(HTMLDivElement | null)[]>([]);
  const mouseRef = useRef({ x: 0, y: 0 });
  const scrollRef = useRef(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    function updateParallax() {
      rafRef.current = null;
      layerElsRef.current.forEach((el, i) => {
        if (!el) return;
        const factor = LAYER_CONFIG[i].parallaxFactor;
        const tx = mouseRef.current.x * factor * 100;
        const ty = mouseRef.current.y * factor * 100;
        const scrollOffset = scrollRef.current * factor * 0.3;
        el.style.transform = `translate3d(${tx}px, ${ty - scrollOffset}px, 0)`;
      });
    }

    function scheduleUpdate() {
      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(updateParallax);
      }
    }

    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current = {
        x: e.clientX / window.innerWidth - 0.5,
        y: e.clientY / window.innerHeight - 0.5,
      };
      scheduleUpdate();
    };

    const mainEl = document.querySelector("main");
    const handleScroll = () => {
      if (!mainEl) return;
      scrollRef.current = mainEl.scrollTop;
      scheduleUpdate();
    };

    window.addEventListener("mousemove", handleMouseMove);
    mainEl?.addEventListener("scroll", handleScroll, { passive: true });

    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      mainEl?.removeEventListener("scroll", handleScroll);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      {/* Deep space gradient */}
      <div className="absolute inset-0 bg-space-radial" />

      {/* Grid overlay */}
      <div className="absolute inset-0 grid-overlay opacity-40" />

      {/* Star layers with parallax */}
      {LAYER_CONFIG.map((_, layerIndex) => (
        <div
          key={layerIndex}
          ref={(el) => {
            layerElsRef.current[layerIndex] = el;
          }}
          className="absolute"
          style={{
            inset: "-20px",
            willChange: "transform",
          }}
        >
          <svg
            className="h-full w-full"
            xmlns="http://www.w3.org/2000/svg"
          >
            {layersRef.current[layerIndex].map((star, i) => (
              <circle
                key={i}
                cx={`${star.x}%`}
                cy={`${star.y}%`}
                r={star.size}
                fill="#00E5FF"
                opacity={star.opacity}
                style={{
                  animation: `star-twinkle ${star.speed}s ease-in-out ${star.delay}s infinite`,
                }}
              />
            ))}
          </svg>
        </div>
      ))}

      {/* Vignette overlay */}
      <div className="absolute inset-0 bg-space-vignette" />

      {/* Subtle nebula glow */}
      <div
        className="absolute -top-1/4 -right-1/4 h-[600px] w-[600px] rounded-full opacity-[0.04]"
        style={{
          background:
            "radial-gradient(circle, #00E5FF 0%, transparent 70%)",
        }}
      />
      <div
        className="absolute -bottom-1/4 -left-1/4 h-[400px] w-[400px] rounded-full opacity-[0.03]"
        style={{
          background:
            "radial-gradient(circle, #0088FF 0%, transparent 70%)",
        }}
      />
    </div>
  );
}
