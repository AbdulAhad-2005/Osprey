// White-label brand name for the operator console. Defaults to "Osprey";
// a downstream build (e.g. the private Ababeel overlay) sets
// NEXT_PUBLIC_BRAND_NAME at build time to rebrand the UI without forking any
// component. NEXT_PUBLIC_* is inlined at build, so set it before `next build`.
export const BRAND = process.env.NEXT_PUBLIC_BRAND_NAME || "Osprey";
export const BRAND_LOWER = BRAND.toLowerCase();
export const IS_DEFAULT_BRAND = BRAND === "Osprey";
