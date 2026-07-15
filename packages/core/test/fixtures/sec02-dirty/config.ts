// Secrets shipped to the browser via public-prefixed env vars.
export const stripe = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;
export const admin = import.meta.env.VITE_ADMIN_TOKEN;
