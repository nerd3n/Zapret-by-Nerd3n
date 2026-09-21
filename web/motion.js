'use strict';

// The Framer Motion Animator workflow informs state transitions and interruption;
// GSAP is the actual animation runtime for this framework-free desktop UI.
(() => {
  const gsap = window.gsap;
  const progressValues = new WeakMap();
  let enabled = false;
  const media = gsap?.matchMedia();
  if (media) media.add('(prefers-reduced-motion: no-preference)', () => {
    enabled = true;
    return () => {
      enabled = false;
      gsap.killTweensOf('.view, #auto-copy, #notification, #auto-progress-fill');
      gsap.set('.view, #auto-copy, #notification', {clearProps: 'opacity,visibility,transform'});
      const fill = document.getElementById('auto-progress-fill');
      if (fill) gsap.set(fill, {scaleX: progressValues.get(fill) || 0, transformOrigin: 'left center'});
    };
  });

  window.ZapretMotion = {
    reveal(element) {
      if (!gsap || !enabled || !element || element.hidden) return;
      gsap.killTweensOf(element);
      gsap.fromTo(element, {autoAlpha: .7, y: 4}, {autoAlpha: 1, y: 0, duration: .2, ease: 'power2.out', overwrite: 'auto', clearProps: 'opacity,visibility,transform'});
    },
    progress(element, value) {
      if (!element) return;
      const next = Math.max(0, Math.min(1, value));
      const previous = progressValues.get(element);
      if (previous === next) return;
      progressValues.set(element, next);
      if (gsap && enabled && previous !== undefined) {
        gsap.to(element, {scaleX: next, transformOrigin: 'left center', duration: .2, ease: 'power2.out', overwrite: 'auto'});
      } else if (gsap) {
        gsap.set(element, {scaleX: next, transformOrigin: 'left center'});
      } else {
        element.style.transform = `scaleX(${next})`;
      }
    }
  };
  window.addEventListener('pagehide', () => media?.revert(), {once: true});
})();
