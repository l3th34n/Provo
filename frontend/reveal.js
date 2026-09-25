/* Presentation only: content stays visible without JavaScript or animation support. */
(() => {
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (motion.matches || !('IntersectionObserver' in window) ||
        !Element.prototype.animate) return;

    const active = new Set();
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(({ target, isIntersecting }) => {
            if (!isIntersecting) return;
            observer.unobserve(target);
            if (motion.matches) return;
            const card = target.matches('.about-card');
            const index = card ? Array.from(target.parentElement.children).indexOf(target) : 0;
            // Animate only on arrival; never hide offscreen content while waiting.
            const animation = target.animate([
                { opacity: 0, translate: `0 ${card ? 28 : 16}px` },
                { opacity: 1, translate: '0 0' }
            ], {
                duration: card ? 650 : 500,
                delay: card ? index * 90 : 0,
                easing: 'cubic-bezier(0.22, 1, 0.36, 1)',
                fill: 'backwards'
            });
            active.add(animation);
            animation.onfinish = animation.oncancel = () => active.delete(animation);
        });
    }, { threshold: 0.08 });

    document.querySelectorAll(
        '#hero .hero-badge, #hero .hero-headline, #hero .hero-subtext, ' +
        '.enterprise-content-section .section-heading, #about .about-card'
    ).forEach((element) => observer.observe(element));

    motion.addEventListener('change', () => {
        if (!motion.matches) return;
        observer.disconnect();
        active.forEach((animation) => animation.cancel());
    });
})();
